"""Score the runtime pipeline on operator-labelled lab captures.

Run: python -m datasets.evaluate_lab LABELS.json [...] [--out report.json]

Captures and label files are read-only inputs. Nothing is sent on a network and
no analyst history is written. Each capture is replayed through a fresh Pipeline
in file order, exactly as the offline CLI would process it. An alert is credited
to the labelled episode of the event that triggered it.
"""
import argparse
import hashlib
import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from datasets.lab_labels import SPLITS, LabelError, load
from detection.pipeline import Pipeline
from ingest.flow_export import FlowExportDecoder, read_flow_export
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader
from ml.model import ARTIFACT
from schemas.enums import ThreatClass
from schemas.traffic_event import TrafficEvent

FORMAT = 'ps26145-lab-evaluation/1'
THREATS = [threat.value for threat in ThreatClass]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_events(path, ingest, source='packets'):
    """Yield TrafficEvents from PCAP, flow-export PCAP or JSONL; drop counts land in ingest."""
    if source == 'flow_export':
        decoder = FlowExportDecoder()
        yield from read_flow_export(path, decoder)
        ingest.update(decoder.stats)
        return
    if path.suffix.lower() == '.pcap':
        reader = PcapReader()
        for batch in reader.read_packets(path):
            for flow, dns, tls in batch:
                yield from_packet(flow, dns, tls)
        ingest.update(reader.parser.dlq.get_stats())
        return
    with path.open(encoding='utf-8') as file:
        for number, line in enumerate(file, 1):
            if line.strip():
                try:
                    yield TrafficEvent.model_validate_json(line)
                except ValidationError as exc:
                    raise ValueError(f'{path}:{number}: invalid TrafficEvent ({exc.error_count()} errors)') from exc


def evaluate_capture(labels, dns_tunnel_candidate=False):
    pipeline = Pipeline(dns_tunnel_candidate=dns_tunnel_candidate)
    episodes = {episode.id: dict(id=episode.id, label=episode.label, scenario=episode.scenario,
                                 tool=episode.tool, start_ms=episode.start_ms, end_ms=episode.end_ms,
                                 events=0, first_event_ms=None, alerts=Counter(), first_correct=None)
                for episode in labels.episodes}
    background = dict(events=0, alerts=Counter())
    ingest, events, ambiguous = {}, 0, 0
    for event in read_events(labels.capture, ingest, labels.source):
        matches = labels.matching(event)
        ambiguous += len(matches) > 1
        alerts = pipeline.process(event)
        events += 1
        target = episodes[matches[0].id] if matches else background
        target['events'] += 1
        if matches and target['first_event_ms'] is None:
            target['first_event_ms'] = event.timestamp
        for alert in alerts:
            target['alerts'][alert.threat_class] += 1
            if matches and alert.threat_class == target['label'] and target['first_correct'] is None:
                target['first_correct'] = dict(
                    timestamp_ms=alert.timestamp, events_into_episode=target['events'],
                    time_to_detect_ms=alert.timestamp - target['first_event_ms'])
    results = []
    for episode in episodes.values():
        alerts = episode.pop('alerts')
        first = episode.pop('first_correct')
        correct = alerts[episode['label']] if episode['label'] != 'BENIGN' else 0
        results.append(episode | dict(
            observed=episode['events'] > 0,
            detected=first is not None,
            correct_alerts=correct,
            other_alerts=dict(sorted((k, v) for k, v in alerts.items() if k != episode['label'])),
            first_correct_alert=first))
    return dict(label_file=str(labels.path), label_sha256=sha256(labels.path),
                capture=str(labels.capture), capture_sha256=sha256(labels.capture),
                split=labels.split, source=labels.source, events=events, late_events=pipeline.extractor.late_events,
                ambiguous_events=ambiguous, ingest=ingest, episodes=results,
                background=dict(events=background['events'],
                                alerts=dict(sorted(background['alerts'].items()))))


def _ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def summarize(captures):
    """Aggregate per-threat episode recall, alert precision and benign false alerts."""
    threat_episodes = [e for c in captures for e in c['episodes'] if e['label'] != 'BENIGN']
    benign_episodes = [e for c in captures for e in c['episodes'] if e['label'] == 'BENIGN']
    benign_alerts = Counter()
    for capture in captures:
        benign_alerts.update(capture['background']['alerts'])
    for episode in benign_episodes:
        benign_alerts.update(episode['other_alerts'])
    benign_events = (sum(c['background']['events'] for c in captures)
                     + sum(e['events'] for e in benign_episodes))
    emitted = Counter(benign_alerts)
    for episode in threat_episodes:
        emitted[episode['label']] += episode['correct_alerts']
        emitted.update(episode['other_alerts'])
    threats = {}
    for threat in THREATS:
        labelled = [e for e in threat_episodes if e['label'] == threat]
        detected = [e for e in labelled if e['detected']]
        correct = sum(e['correct_alerts'] for e in labelled)
        delays = [e['first_correct_alert']['time_to_detect_ms'] for e in detected]
        threats[threat] = dict(
            episodes=len(labelled), observed_episodes=sum(e['observed'] for e in labelled),
            detected_episodes=len(detected), episode_recall=_ratio(len(detected), len(labelled)),
            alerts=emitted[threat], correct_alerts=correct,
            alert_precision=_ratio(correct, emitted[threat]),
            false_alerts_on_benign=benign_alerts[threat],
            median_time_to_detect_ms=statistics.median(delays) if delays else None,
            max_time_to_detect_ms=max(delays) if delays else None)
    scenarios = {}
    for episode in threat_episodes + benign_episodes:
        row = scenarios.setdefault(episode['scenario'], dict(label=episode['label'], episodes=0,
                                                             detected=0, with_any_alert=0))
        row['episodes'] += 1
        row['detected'] += episode['detected']
        row['with_any_alert'] += bool(episode['correct_alerts'] or episode['other_alerts'])
    return dict(
        captures=len(captures), events=sum(c['events'] for c in captures),
        late_events=sum(c['late_events'] for c in captures),
        ambiguous_events=sum(c['ambiguous_events'] for c in captures),
        threats=threats,
        benign=dict(events=benign_events, alerts=dict(sorted(benign_alerts.items())),
                    false_alerts_per_1000_events=_ratio(1000 * sum(benign_alerts.values()), benign_events),
                    labelled_episodes=len(benign_episodes),
                    labelled_episodes_with_alerts=sum(bool(e['other_alerts']) for e in benign_episodes)),
        scenarios=dict(sorted(scenarios.items())))


def evaluate(label_paths, dns_tunnel_candidate=False):
    captures = [evaluate_capture(load(path), dns_tunnel_candidate) for path in label_paths]
    summary = {'all': summarize(captures)}
    for split in SPLITS:
        members = [c for c in captures if c['split'] == split]
        if members:
            summary[split] = summarize(members)
    pipeline = Pipeline(dns_tunnel_candidate=dns_tunnel_candidate)
    return dict(format=FORMAT, generated_at_utc=datetime.now(timezone.utc).isoformat(),
                pipeline=dict(dns_tunnel_candidate=dns_tunnel_candidate,
                              dga_model_enabled=pipeline.dga_model.enabled,
                              model_sha256=sha256(ARTIFACT)),
                scope=('Runtime alerts on operator-labelled lab captures. Episode recall counts an '
                       'episode once it has one alert of its labelled class; precision is per alert. '
                       'Labels are only as reliable as the operator ground truth.'),
                captures=captures, summary=summary)


def table(summary):
    lines = [f"{'threat':<20}{'episodes':>9}{'detected':>9}{'recall':>8}"
             f"{'alerts':>8}{'precision':>10}{'benign FA':>10}{'median TTD ms':>15}"]
    for threat, row in summary['threats'].items():
        if not row['episodes'] and not row['alerts']:
            continue
        fmt = lambda v: '-' if v is None else f'{v:.2f}' if isinstance(v, float) else str(v)
        lines.append(f"{threat:<20}{row['episodes']:>9}{row['detected_episodes']:>9}"
                     f"{fmt(row['episode_recall']):>8}{row['alerts']:>8}{fmt(row['alert_precision']):>10}"
                     f"{row['false_alerts_on_benign']:>10}{fmt(row['median_time_to_detect_ms']):>15}")
    benign = summary['benign']
    lines.append(f"benign events {benign['events']}, false alerts/1000 events "
                 f"{'-' if benign['false_alerts_per_1000_events'] is None else benign['false_alerts_per_1000_events']}, "
                 f"labelled benign episodes with alerts {benign['labelled_episodes_with_alerts']}/{benign['labelled_episodes']}")
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Score runtime alerts against labelled lab captures (read-only).')
    parser.add_argument('labels', nargs='+', type=Path, help='ps26145-lab-labels/1 JSON files')
    parser.add_argument('--out', type=Path, help='write the JSON report here')
    parser.add_argument('--dns-tunnel-candidate', action='store_true',
                        help='score the disabled DNS-tunnel candidate instead of the default rule')
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.labels, args.dns_tunnel_candidate)
    except (LabelError, ValueError, OSError) as exc:
        parser.exit(2, f'error: {exc}\n')
    if args.out:
        inputs = {Path(c[key]).resolve() for c in report['captures'] for key in ('label_file', 'capture')}
        if args.out.resolve() in inputs:
            parser.exit(2, 'error: --out would overwrite a read-only input\n')
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for name, summary in report['summary'].items():
        print(f'== {name}: {summary["captures"]} capture(s), {summary["events"]} events, '
              f'{summary["late_events"]} late, {summary["ambiguous_events"]} ambiguous')
        print(table(summary))
    return 0


if __name__ == '__main__':
    sys.exit(main())

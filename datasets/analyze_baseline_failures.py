"""Attribution of already evaluated development failures; no candidate changes.

Reconstructs only recorded false-positive scenarios with the frozen runtime.
Other rows retain their historical verdicts; they are not new quality metrics.
No fitting, tuning, ablation or reserved-data evaluation is performed.
"""
import argparse
import hashlib
import importlib
import json
from collections import Counter, defaultdict, deque
from pathlib import Path

from detection.pipeline import Pipeline
from features.extractor import FEATURES, FeatureExtractor
from ml.model import ARTIFACT, vector

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('UDP', 'validate_udp_flood', 'udp_flood_development', 'DDOS'),
    ('C2', 'validate_c2_beacon', 'c2_beacon_development', 'BOTNET_C2'),
    ('RECON', 'validate_recon', 'recon_development', 'RECONNAISSANCE'),
    ('EXFIL', 'validate_exfil', 'exfil_development', 'DATA_EXFILTRATION'),
    ('ENCRYPTED', 'validate_encrypted', 'encrypted_session_validation', 'ENCRYPTED_MALWARE'),
)
SPOOF_SOURCE = ('SPOOF', 'validate_spoofed_source', 'spoofed_source_validation', 'DDOS')
SPOOF_MODEL_SHA256 = '4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010'


def stream_digest(stream):
    raw = json.dumps([event.model_dump(mode='json') for event in stream],
                     sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def generator_matches_report(raw, expected):
    # The release checkout hashed CRLF text; current local sources have LF.
    lf = raw.replace(b'\r\n', b'\n')
    return expected in {hashlib.sha256(item).hexdigest()
                        for item in (raw, lf, lf.replace(b'\n', b'\r\n'))}


def attribution(alert, predicted, posterior, target):
    source = str(alert.detection_source)
    if source not in ('RULE', 'ML', 'HYBRID'):
        raise ValueError('Unknown alert attribution')
    model_hit = predicted == target and posterior >= .8
    if model_hit != (source in ('ML', 'HYBRID')):
        raise ValueError('Model prediction disagrees with alert attribution')
    return dict(detection_source=source, model_label=predicted, model_posterior=posterior,
                target_model_hit=model_hit, target_rule_hit=source in ('RULE', 'HYBRID'))


def replay_first(stream, target, saved):
    """Observe actual runtime inputs/predictions, retaining its real decisions."""
    runtime = Pipeline()
    captured = {}
    original = runtime.model.predict

    def observe(features):
        label, posterior = original(features)
        captured.update(features=features, label=label, posterior=posterior)
        return label, posterior

    runtime.model.predict = observe
    for index, event in enumerate(stream, start=1):
        for alert in runtime.process(event):
            if str(alert.threat_class) != target:
                continue
            if index != saved['event'] or alert.raw_evidence_metrics != saved['evidence']:
                raise ValueError('Current first-alert position/evidence differs from saved evaluation')
            if 'detection_source' in saved and str(alert.detection_source) != saved['detection_source']:
                raise ValueError('Current attribution differs from saved evaluation')
            return dict(event=index, elapsed_seconds=(event.timestamp-stream[0].timestamp)/1000,
                        evidence=alert.raw_evidence_metrics,
                        runtime_features=captured['features'],
                        **attribution(alert, captured['label'], captured['posterior'], target))
    raise ValueError('Recorded false positive no longer reproduces; do not silently relabel it')


def feature_digest(stream):
    extractor = FeatureExtractor()
    rows = [vector(extractor.update(event)) for event in stream]
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def overlaps(streams, positives):
    """Exact raw-event and model-feature collisions, not statistical accuracy."""
    groups = {}
    for name, stream in streams.items():
        key = feature_digest(stream)
        groups.setdefault(key, []).append(name)
    result = []
    for digest, names in groups.items():
        yes = [name for name in names if positives[name]]
        no = [name for name in names if not positives[name]]
        if yes and no:
            result.append(dict(model_feature_sequence_sha256=digest, positives=yes, benign=no,
                               identical_raw_event_pairs=[[a, b] for a in yes for b in no
                                                          if stream_digest(streams[a]) == stream_digest(streams[b])]))
    return result


def udp_collision_detail(positive, benign):
    """Compare exposed paired metadata, never infer intent from its port."""
    if not positive or len(positive) != len(benign):
        raise ValueError('Collision detail requires nonempty aligned event counts')
    if any(event.protocol != 17 for stream in (positive, benign) for event in stream):
        raise ValueError('Collision detail accepts UDP metadata only')
    left = [event.model_dump(mode='json') for event in positive]
    right = [event.model_dump(mode='json') for event in benign]
    differences = sorted({key for a, b in zip(left, right) for key in a if a[key] != b[key]})
    a_extractor, b_extractor = FeatureExtractor(), FeatureExtractor()
    a_features = [a_extractor.update(event) for event in positive]
    b_features = [b_extractor.update(event) for event in benign]
    return dict(metadata_identical=left == right, different_metadata_fields=differences,
                differing_values={key:dict(positive=sorted({str(row[key]) for row in left}),
                                          benign=sorted({str(row[key]) for row in right}))
                                  for key in differences},
                complete_runtime_features_identical=a_features == b_features,
                model_vectors_identical=[vector(row) for row in a_features] ==
                                        [vector(row) for row in b_features],
                udp_rate_rule_decisions_identical=
                    [row['udp_target_packet_rate'] >= 1000 for row in a_features] ==
                    [row['udp_target_packet_rate'] >= 1000 for row in b_features])


def c2_history_detail(stream):
    """Trace exposed causal features without prediction or alternate horizons."""
    from datasets.validate_c2_beacon import feature_snapshot

    if not stream or any(b.timestamp < a.timestamp for a, b in zip(stream, stream[1:])):
        raise ValueError('C2 history requires nonempty timestamp-ordered metadata')
    extractor = FeatureExtractor()
    snapshots = [feature_snapshot(extractor, event, extractor.update(event)) for event in stream]
    return dict(max_peer_history_count=max(row['peer_history_count'] for row in snapshots),
                first_eight_peer_event=next((i for i, row in enumerate(snapshots, 1)
                                            if row['peer_history_count'] >= 8), None),
                final_audited_features=snapshots[-1])


def c2_pair_detail(positive, benign):
    """Separate timing-rule collisions from full observations/model collisions."""
    if not positive or len(positive) != len(benign):
        raise ValueError('C2 pairs require nonempty aligned event counts')
    left = [event.model_dump(mode='json') for event in positive]
    right = [event.model_dump(mode='json') for event in benign]
    a_extractor, b_extractor = FeatureExtractor(), FeatureExtractor()
    a_features = [a_extractor.update(event) for event in positive]
    b_features = [b_extractor.update(event) for event in benign]
    if any(row is None for row in a_features + b_features):
        raise ValueError('C2 pairs require timestamp-ordered metadata')

    def rule(row):
        return row['history_count'] >= 8 and row['iat_mean'] >= 1 and row['iat_cv'] < .05

    different_features = sorted({key for a, b in zip(a_features, b_features)
                                 for key in a if a[key] != b[key]})
    return dict(metadata_identical=left == right,
                different_metadata_fields=sorted({key for a, b in zip(left, right)
                                                  for key in a if a[key] != b[key]}),
                complete_runtime_features_identical=a_features == b_features,
                different_runtime_features=different_features,
                different_model_features=[key for key in different_features if key in FEATURES],
                model_vectors_identical=[vector(row) for row in a_features] ==
                                        [vector(row) for row in b_features],
                c2_rule_decisions_identical=[rule(row) for row in a_features] ==
                                            [rule(row) for row in b_features])


def spoof_history_detail(stream):
    """Reconstruct only the existing disabled predicate's causal evidence."""
    from types import SimpleNamespace
    from datasets.validate_spoofed_source import VICTIM, diagnostic_indicator, snapshot

    if (not stream or any(event.protocol != 17 for event in stream)
            or any(b.timestamp < a.timestamp for a, b in zip(stream, stream[1:]))):
        raise ValueError('Spoof history requires nonempty timestamp-ordered UDP metadata')
    extractor = FeatureExtractor()
    view = SimpleNamespace(extractor=extractor)
    observations = defaultdict(deque)
    feature_sequence = hashlib.sha256()
    first = final = None
    for index, event in enumerate(stream, 1):
        extractor.update(event)  # No Pipeline/model prediction for this trace.
        target, second = str(event.dst_ip), int(event.timestamp // 1000)
        history = observations[target]
        while history and history[0][0] < second - 10:
            history.popleft()
        history.append((second, str(event.src_ip)))
        final = snapshot(view, observations[VICTIM])
        feature_sequence.update(json.dumps(final, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        if target == VICTIM and first is None and diagnostic_indicator(final):
            first = dict(event=index, timestamp=event.timestamp, features=final,
                         wording='consistent with suspected spoofed-source flood')
    return dict(first_disabled_indicator=first, final_visible_features=final,
                diagnostic_feature_sequence_sha256=feature_sequence.hexdigest())


def recon_history_detail(stream):
    """Audit exposed one-packet TCP fan-out against causal prefix references."""
    from datasets.validate_recon import reference

    if (not stream or any(event.protocol != 6 or event.packets != 1 for event in stream)
            or len({str(event.src_ip) for event in stream}) != 1
            or any(b.timestamp < a.timestamp for a, b in zip(stream, stream[1:]))):
        raise ValueError('Recon history requires ordered single-source one-packet TCP metadata')
    extractor, seen = FeatureExtractor(), []
    maximum_hosts = maximum_ports = 0
    first_guard = first_rule = final = None
    trace = hashlib.sha256()
    for index, event in enumerate(stream, 1):
        seen.append(event)
        features = extractor.update(event)
        final = reference(seen, event)
        if any(features[key] != final[key]
               for key in ('destination_count', 'port_count', 'syn_fraction')):
            raise ValueError('Recon causal features disagree with independent reference')
        maximum_hosts = max(maximum_hosts, final['destination_count'])
        maximum_ports = max(maximum_ports, final['port_count'])
        trace.update(json.dumps(final, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        evidence = dict(event=index, elapsed_seconds=(event.timestamp-stream[0].timestamp)/1000,
                        reference=final)
        fanout = max(features['destination_count'], features['port_count'])
        if first_guard is None and fanout >= 10:
            first_guard = evidence
        if first_rule is None and fanout >= 20:
            first_rule = evidence
    return dict(max_destination_hosts_ten_seconds=maximum_hosts,
                max_destination_ports_ten_seconds=maximum_ports,
                first_model_guard_eligible=first_guard, first_rule_eligible=first_rule,
                final_reference=final, causal_reference_sequence_sha256=trace.hexdigest())


def recon_pair_detail(positive, benign):
    """Distinguish complete collisions from an identical shorter benign prefix."""
    if (not positive or not benign or len(positive) < len(benign)
            or any(event.protocol != 6 or event.packets != 1 for event in positive + benign)
            or any(b.timestamp < a.timestamp for stream in (positive, benign)
                   for a, b in zip(stream, stream[1:]))):
        raise ValueError('Recon pairs require ordered TCP metadata with a nonempty aligned benign prefix')
    length = len(benign)
    left = [event.model_dump(mode='json') for event in positive[:length]]
    right = [event.model_dump(mode='json') for event in benign]
    a_extractor, b_extractor = FeatureExtractor(), FeatureExtractor()
    a_features = [a_extractor.update(event) for event in positive[:length]]
    b_features = [b_extractor.update(event) for event in benign]
    same_length = len(positive) == length
    same_vectors = [vector(row) for row in a_features] == [vector(row) for row in b_features]
    return dict(positive_events=len(positive), benign_events=length,
                compared_prefix_events=length, metadata_prefix_identical=left == right,
                complete_metadata_identical=same_length and left == right,
                runtime_feature_prefix_identical=a_features == b_features,
                complete_runtime_features_identical=same_length and a_features == b_features,
                model_vector_prefix_identical=same_vectors,
                complete_model_vectors_identical=same_length and same_vectors)


def analyze(group=None):
    if group not in (None, 'UDP', 'C2', 'SPOOF', 'RECON'):
        raise ValueError('Only UDP, C2, SPOOF and RECON have a scoped diagnostic selection')
    model_hash = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    if group == 'SPOOF' and model_hash != SPOOF_MODEL_SHA256:
        raise ValueError('Spoof diagnosis requires the unchanged frozen baseline model')
    modules = []
    sources = (SPOOF_SOURCE,) if group == 'SPOOF' else SOURCES
    for selected_group, module_name, report_name, target in sources:
        if group is not None and selected_group != group:
            continue
        path = ROOT/f'docs/verification/release-audit/{report_name}.json'
        raw_report = path.read_bytes()
        report = json.loads(raw_report)
        module = importlib.import_module(f'datasets.{module_name}')
        source_name = f'datasets/{module_name}.py'
        if not generator_matches_report((ROOT/source_name).read_bytes(), report['source_sha256'][source_name]):
            raise ValueError(f'Changed scenario generator: {selected_group}')
        if 'ml/artifact.json' in report['source_sha256'] and report['source_sha256']['ml/artifact.json'] != model_hash:
            raise ValueError('Historical report uses a different model')
        rows = report.get('scenarios', report.get('rows'))
        saved_counts = report['existing_ddos_counts'] if group == 'SPOOF' else report['counts']
        if group == 'SPOOF':
            # Adapt the historical nested report, without changing its bytes or
            # including this additional subtype in the frozen default all-group run.
            rows = [row | dict(verdict=row['existing_ddos']['verdict'],
                               first_alert=row['existing_ddos']['first']) for row in rows]
        lookup = {row['scenario']: row for row in rows}
        if set(lookup) != {case[0] for case in module.CASES}:
            raise ValueError('Scenario inventory differs from previously evaluated cases')
        streams, positives, failures = {}, {}, []
        for case_index, case in enumerate(module.CASES):
            name, positive = case[:2]
            row = lookup[name]
            if selected_group == 'UDP':
                if row['positive'] is not positive or row['format'] != case[2]:
                    raise ValueError('UDP labels/format differ from saved development cases')
                stream = list(module.raw_events(name) if case[2] == 'raw' else module.aggregate_events(name))
            elif selected_group == 'ENCRYPTED':
                stream = list(module.events(case, case_index))
            else:
                stream = list(module.events(*case[2:]))
            if selected_group == 'C2' and group == 'C2' and row['ground_truth_c2'] is not positive:
                raise ValueError('C2 labels differ from saved development cases')
            if selected_group == 'RECON' and group == 'RECON' and row['ground_truth_unauthorised_scan'] is not positive:
                raise ValueError('Recon labels differ from saved development cases')
            if group == 'SPOOF' and row['ground_truth_forged'] is not positive:
                raise ValueError('Spoof labels differ from saved development cases')
            digest = stream_digest(stream)
            recorded_digest = row.get('observed_stream_sha256', row.get('stream_sha256'))
            if len(stream) != row['events'] or (recorded_digest and digest != recorded_digest):
                raise ValueError(f'Changed previously evaluated stream: {selected_group}/{name}')
            streams[name], positives[name] = stream, positive
            if row['verdict'] == 'FP':
                if positive:
                    raise ValueError('False positive is not labelled benign')
                failures.append(dict(scenario=name, verdict='FP', stream_sha256=digest,
                                     first_alert=replay_first(stream, target, row['first_alert'])))
            elif row['verdict'] == 'FN':
                failures.append(dict(scenario=name, verdict='FN', saved_row=row))
        counts = Counter(row['verdict'] for row in rows)
        if any(counts[key] != value for key, value in saved_counts.items()):
            raise ValueError('Saved counts disagree with saved scenario verdicts')
        collisions = overlaps(streams, positives)
        if selected_group == 'UDP' and group == 'UDP':
            for collision in collisions:
                collision['paired_observability'] = [
                    dict(positive=a, benign=b, **udp_collision_detail(streams[a], streams[b]))
                    for a in collision['positives'] for b in collision['benign']]
        modules.append(dict(group=selected_group, threat_class=target, saved_counts=saved_counts,
                            report=path.relative_to(ROOT).as_posix(),
                            report_sha256=hashlib.sha256(raw_report).hexdigest(),
                            failures=failures, opposite_label_overlaps=collisions))
        if selected_group == 'RECON' and group == 'RECON':
            histories = {name: recon_history_detail(stream) for name, stream in streams.items()}
            for name, history in histories.items():
                if any(history[key] != lookup[name][key] for key in
                       ('max_destination_hosts_ten_seconds', 'max_destination_ports_ten_seconds', 'final_reference')):
                    raise ValueError('Recon causal history differs from saved development evidence')
            modules[-1]['causal_histories'] = histories
            modules[-1]['paired_observability'] = [
                dict(positive=a, benign=b, **recon_pair_detail(streams[a], streams[b]))
                for a, b in [('vertical_scan', 'authorised_vulnerability_scanner'),
                             ('horizontal_scan', 'authorised_asset_inventory'),
                             ('horizontal_scan', 'service_discovery')]]
        if selected_group == 'C2' and group == 'C2':
            histories = {name: c2_history_detail(stream) for name, stream in streams.items()}
            for name, history in histories.items():
                if any(history[key] != lookup[name][key]
                       for key in ('max_peer_history_count', 'final_audited_features')):
                    raise ValueError('C2 causal history differs from saved development evidence')
            modules[-1]['causal_histories'] = histories
            modules[-1]['same_timing_pairs'] = [
                dict(positive=a[0], benign=b[0], **c2_pair_detail(streams[a[0]], streams[b[0]]))
                for a in module.CASES if a[1] for b in module.CASES if not b[1] and a[2] == b[2]]
        if group == 'SPOOF':
            histories = {name: spoof_history_detail(stream) for name, stream in streams.items()}
            for name, history in histories.items():
                row = lookup[name]
                if (history['final_visible_features'] != row['final_visible_features']
                        or history['first_disabled_indicator'] != row['diagnostic_only_indicator']['first']):
                    raise ValueError('Spoof causal history differs from saved development evidence')
            indicator_counts = Counter(row['diagnostic_only_indicator']['verdict'] for row in rows)
            if any(indicator_counts[key] != value for key, value in report['diagnostic_only_indicator_counts'].items()):
                raise ValueError('Saved spoof predicate counts disagree with saved verdicts')
            modules[-1].update(causal_histories=histories,
                               saved_disabled_indicator_counts=report['diagnostic_only_indicator_counts'],
                               historical_report_model_pin_absent=True,
                               baseline_model_reference_sha256=SPOOF_MODEL_SHA256,
                               same_rate_telemetry_comparison=udp_collision_detail(
                                   streams['forged_32_once'], streams['authorised_telemetry_32']))
            modules[-1]['same_rate_telemetry_comparison']['disabled_indicator_feature_sequences_identical'] = (
                histories['forged_32_once']['diagnostic_feature_sequence_sha256'] ==
                histories['authorised_telemetry_32']['diagnostic_feature_sequence_sha256'])
            for collision in collisions:
                collision['paired_observability'] = [
                    dict(positive=a, benign=b, **udp_collision_detail(streams[a], streams[b]))
                    for a in collision['positives'] for b in collision['benign']]
    fp_sources = Counter(item['first_alert']['detection_source']
                         for module in modules for item in module['failures'] if item['verdict'] == 'FP')
    return dict(scope='Failure analysis of already evaluated development cases; attribution replay, not a new quality evaluation',
                model_sha256=model_hash, modules=modules, first_false_positive_sources=dict(fp_sources),
                policy=dict(fit=False, tuning=False, ablation=False, reserved_data=False,
                            runtime_changes=False, positive_quality_replay=False),
                current_source_sha256={name: hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                                       for name in ('detection/pipeline.py','features/extractor.py','ml/model.py',
                                                    'features/rate_window.py','datasets/analyze_baseline_failures.py')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', choices=['UDP', 'C2', 'SPOOF', 'RECON'], help='Inspect one subtype only; default retains the historical all-group diagnostic')
    args = parser.parse_args()
    report = analyze(group=args.group)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as file:
        json.dump(report, file, indent=2, allow_nan=False)
        file.write('\n')
    print(json.dumps({'first_false_positive_sources': report['first_false_positive_sources'],
                      'groups': {module['group']: module['saved_counts'] for module in report['modules']}},indent=2))


if __name__ == '__main__':
    main()

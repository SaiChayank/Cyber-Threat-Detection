"""Attribution of already evaluated development failures; no candidate changes.

Reconstructs only recorded false-positive scenarios with the frozen runtime.
Other rows retain their historical verdicts; they are not new quality metrics.
No fitting, tuning, ablation or reserved-data evaluation is performed.
"""
import argparse
import hashlib
import importlib
import json
from collections import Counter
from pathlib import Path

from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from ml.model import ARTIFACT, vector

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('UDP', 'validate_udp_flood', 'udp_flood_development', 'DDOS'),
    ('C2', 'validate_c2_beacon', 'c2_beacon_development', 'BOTNET_C2'),
    ('RECON', 'validate_recon', 'recon_development', 'RECONNAISSANCE'),
    ('EXFIL', 'validate_exfil', 'exfil_development', 'DATA_EXFILTRATION'),
    ('ENCRYPTED', 'validate_encrypted', 'encrypted_session_validation', 'ENCRYPTED_MALWARE'),
)


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


def analyze():
    model_hash = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    modules = []
    for group, module_name, report_name, target in SOURCES:
        path = ROOT/f'docs/verification/release-audit/{report_name}.json'
        raw_report = path.read_bytes()
        report = json.loads(raw_report)
        module = importlib.import_module(f'datasets.{module_name}')
        source_name = f'datasets/{module_name}.py'
        if not generator_matches_report((ROOT/source_name).read_bytes(), report['source_sha256'][source_name]):
            raise ValueError(f'Changed scenario generator: {group}')
        if 'ml/artifact.json' in report['source_sha256'] and report['source_sha256']['ml/artifact.json'] != model_hash:
            raise ValueError('Historical report uses a different model')
        rows = report.get('scenarios', report.get('rows'))
        lookup = {row['scenario']: row for row in rows}
        if set(lookup) != {case[0] for case in module.CASES}:
            raise ValueError('Scenario inventory differs from previously evaluated cases')
        streams, positives, failures = {}, {}, []
        for case_index, case in enumerate(module.CASES):
            name, positive = case[:2]
            row = lookup[name]
            if group == 'UDP':
                stream = list(module.raw_events(name) if case[2] == 'raw' else module.aggregate_events(name))
            elif group == 'ENCRYPTED':
                stream = list(module.events(case, case_index))
            else:
                stream = list(module.events(*case[2:]))
            digest = stream_digest(stream)
            recorded_digest = row.get('observed_stream_sha256', row.get('stream_sha256'))
            if len(stream) != row['events'] or (recorded_digest and digest != recorded_digest):
                raise ValueError(f'Changed previously evaluated stream: {group}/{name}')
            streams[name], positives[name] = stream, positive
            if row['verdict'] == 'FP':
                if positive:
                    raise ValueError('False positive is not labelled benign')
                failures.append(dict(scenario=name, verdict='FP', stream_sha256=digest,
                                     first_alert=replay_first(stream, target, row['first_alert'])))
            elif row['verdict'] == 'FN':
                failures.append(dict(scenario=name, verdict='FN', saved_row=row))
        counts = Counter(row['verdict'] for row in rows)
        if any(counts[key] != value for key, value in report['counts'].items()):
            raise ValueError('Saved counts disagree with saved scenario verdicts')
        modules.append(dict(group=group, threat_class=target, saved_counts=report['counts'],
                            report=path.relative_to(ROOT).as_posix(),
                            report_sha256=hashlib.sha256(raw_report).hexdigest(),
                            failures=failures, opposite_label_overlaps=overlaps(streams, positives)))
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
    args = parser.parse_args()
    report = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as file:
        json.dump(report, file, indent=2, allow_nan=False)
        file.write('\n')
    print(json.dumps({'first_false_positive_sources': report['first_false_positive_sources'],
                      'groups': {module['group']: module['saved_counts'] for module in report['modules']}},indent=2))


if __name__ == '__main__':
    main()

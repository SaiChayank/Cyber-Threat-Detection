"""Offline, scenario-level audit of the existing encrypted metadata detector.

Generated events are controlled development diagnostics, not malware captures or
an independent reserved evaluation set. No network traffic or payload is used.
"""
import hashlib
import json
from pathlib import Path

from detection.pipeline import Pipeline
from features.extractor import DEMO_FINGERPRINT, FeatureExtractor
from ml.model import Model
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0
OTHER_JA3 = hashlib.md5(b'771,4865-4866-4867,0-10-11-13-16,29-23,0').hexdigest()
THIRD_JA3 = hashlib.md5(b'771,49196-49200,0-11-13-35,23-24,0').hexdigest()

# Scenario groups, not individual event rows, are the unit of analysis. The same
# source/destination pool is shared across positive and benign cases; neither
# addresses nor group names enter the runtime feature vector.
CASES = (
    ('lab_tls_stable', True, 'lab_a', 'TLS', DEMO_FINGERPRINT, 'small_stable', 'steady'),
    ('lab_tls_bursty', True, 'lab_b', 'TLS', DEMO_FINGERPRINT, 'small_stable', 'bursty'),
    ('novel_tls_stable', True, 'novel_a', 'TLS', OTHER_JA3, 'small_stable', 'steady'),
    ('novel_tls_variable', True, 'novel_b', 'TLS', THIRD_JA3, 'variable', 'steady'),
    ('tls_no_hello', True, 'no_hello', 'TLS', None, 'small_stable', 'steady'),
    ('quic_stable', True, 'quic_a', 'QUIC', None, 'small_stable', 'steady'),
    ('quic_variable', True, 'quic_b', 'QUIC', None, 'variable', 'bursty'),
    ('tls_sparse', True, 'sparse', 'TLS', OTHER_JA3, 'small_stable', 'sparse'),
    ('browser_tls', False, 'browser', 'TLS', OTHER_JA3, 'variable', 'bursty'),
    ('software_update', False, 'updater', 'TLS', THIRD_JA3, 'large', 'steady'),
    ('api_client', False, 'api', 'TLS', OTHER_JA3, 'small_stable', 'steady'),
    ('ordinary_encrypted_app', False, 'app', 'TLS', None, 'variable', 'bursty'),
    ('browser_shared_ja3', False, 'browser_shared', 'TLS', DEMO_FINGERPRINT, 'variable', 'bursty'),
    ('update_shared_ja3', False, 'update_shared', 'TLS', DEMO_FINGERPRINT, 'large', 'steady'),
    ('api_low_variance', False, 'api_low_variance', 'TLS', THIRD_JA3, 'small_stable', 'steady'),
    ('ordinary_quic', False, 'quic_app', 'QUIC', None, 'variable', 'steady'),
    ('quic_small_stable', False, 'quic_telemetry', 'QUIC', None, 'small_stable', 'steady'),
    ('unparsed_port_443', False, 'unparsed', 'IP', None, 'small_stable', 'steady'),
)


def events(case, case_index):
    _, _, _, transport, fingerprint, sizes, timing = case
    t = START + case_index * 86_400_000
    for index in range(20):
        if index:
            delta = (12_000 if timing == 'sparse' else
                     (600, 2100, 900, 4400)[index % 4] if timing == 'bursty' else 2500)
            t += delta
        size = (512 + index % 3 if sizes == 'small_stable' else
                (180, 1430, 270, 970, 420)[index % 5] if sizes == 'variable' else
                80_000 + 1000 * (index % 4))
        yield TrafficEvent(timestamp=t, src_ip=f'10.0.0.{10 + case_index % 4}',
                           dst_ip=f'198.51.100.{20 + case_index % 4}',
                           src_port=49152, dst_port=443,
                           protocol=17 if transport == 'QUIC' else 6,
                           packets=1, bytes=size, encrypted=True, transport=transport,
                           tls_fingerprint=fingerprint if index == 0 else None)


def score(case, case_index):
    name, positive, group, transport, fingerprint, sizes, timing = case
    stream = list(events(case, case_index))
    runtime = Pipeline()
    audit = FeatureExtractor()
    model = Model()
    first = None
    model_hits = 0
    rule_hits = 0
    for index, event in enumerate(stream, start=1):
        features = audit.update(event)
        predicted, posterior = model.predict(features)
        model_hit = predicted == 'ENCRYPTED_MALWARE' and posterior >= .8
        rule_hit = bool(features['encrypted'] and features['fingerprint_risk'])
        model_hits += model_hit
        rule_hits += rule_hit
        for alert in runtime.process(event):
            if alert.threat_class != 'ENCRYPTED_MALWARE' or first is not None:
                continue
            for key in ('encrypted', 'fingerprint_risk', 'size_cv', 'iat_cv'):
                if alert.raw_evidence_metrics[key] != features[key]:
                    raise AssertionError(f'Runtime evidence mismatch: {key}')
            first = {'event': index, 'elapsed_seconds': (event.timestamp - stream[0].timestamp) / 1000,
                     'detection_source': alert.detection_source,
                     'evidence': alert.raw_evidence_metrics,
                     'model_hit': model_hit, 'rule_hit': rule_hit,
                     'flow_id_present': bool(alert.flow_id), 'timestamp': alert.timestamp,
                     'confidence_score': alert.confidence_score, 'severity': alert.severity}
    early = first is not None and first['event'] < len(stream)
    verdict = ('TP' if early else 'FN') if positive else ('FP' if first else 'TN')
    digest = hashlib.sha256(json.dumps([event.model_dump(mode='json') for event in stream],
                                       sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'scenario': name, 'ground_truth_malicious_like': positive, 'group': group,
            'transport': transport, 'initial_ja3': fingerprint,
            'size_pattern': sizes, 'timing_pattern': timing,
            'events': len(stream), 'stream_sha256': digest,
            'model_hit_events': model_hits, 'rule_hit_events': rule_hits,
            'first_alert': first, 'verdict': verdict}


def main():
    rows = [score(case, index) for index, case in enumerate(CASES)]
    counts = {key: sum(row['verdict'] == key for row in rows) for key in ('TP', 'TN', 'FP', 'FN')}
    tp, tn, fp, fn = (counts[key] for key in ('TP', 'TN', 'FP', 'FN'))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    report = {
        'scope': 'Controlled synthetic, runtime-compatible metadata diagnostics; no independent reserved/production accuracy',
        'frozen_gate': {'recall_min': .80, 'precision_min': .95, 'fpr_max': .02,
                        'positive_alert_before_final_event': True},
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ('docs/ENCRYPTED_SESSION_VALIDATION.md',
                                       'datasets/validate_encrypted.py', 'detection/pipeline.py',
                                       'features/extractor.py', 'ml/artifact.json')},
        'counts': counts, 'precision': precision, 'recall': recall,
        'f1': 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        'false_positive_rate': fpr,
        'controlled_gate_passed': recall >= .80 and precision >= .95 and fpr <= .02,
        'independent_reserved_evaluation_available': False,
        'rows': rows,
    }
    output = ROOT / 'ml/encrypted_session_validation.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts, 'precision': precision, 'recall': recall,
                      'fpr': fpr, 'controlled_gate_passed': report['controlled_gate_passed'],
                      'false_positives': [r['scenario'] for r in rows if r['verdict'] == 'FP'],
                      'false_negatives': [r['scenario'] for r in rows if r['verdict'] == 'FN']}, indent=2))


if __name__ == '__main__':
    main()

"""Controlled, offline C2-periodicity development replay; no packets are sent."""
import hashlib
import json
from pathlib import Path

from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0


CASES = (
    ('beacon_fixed_2_5', True, 'fixed_2_5', 130),
    ('beacon_fixed_6', True, 'fixed_6', 130),
    ('beacon_fixed_20', True, 'fixed_20', 130),
    ('beacon_jitter_6', True, 'jitter_6', 130),
    ('beacon_persistent_12', True, 'fixed_12', 130),
    ('beacon_rotate_12', True, 'rotate_12', 130),
    ('health_check_2_5', False, 'fixed_2_5', 130),
    ('update_agent_20', False, 'fixed_20', 1024),
    ('telemetry_jitter_6', False, 'jitter_6', 256),
    ('scheduled_poll_60', False, 'fixed_60', 200),
    ('rotating_telemetry_12', False, 'rotate_12', 256),
    ('irregular_browsing', False, 'irregular', 400),
    ('short_periodic_6', False, 'short_6', 130),
    ('intermittent_client', False, 'intermittent', 256),
)


def events(kind, size):
    count = 7 if kind == 'short_6' else 32
    t = START
    for index in range(count):
        if index:
            if kind == 'jitter_6':
                interval = 5.4 if index % 2 else 6.6
            elif kind == 'irregular':
                interval = (1, 5, 2, 13, 3, 17, 8)[(index - 1) % 7]
            elif kind == 'intermittent':
                interval = (5, 5, 30, 120)[(index - 1) % 4]
            elif kind.startswith('fixed_'):
                interval = float(kind.removeprefix('fixed_').replace('_', '.'))
            else:
                interval = float(kind.rsplit('_', 1)[1])
            t += interval * 1000
        target = (f'198.51.100.{20 + index % 12}' if kind == 'irregular' else
                  f'198.51.100.{20 + index % 2}' if kind == 'rotate_12' else
                  '198.51.100.20')
        yield TrafficEvent(timestamp=t, src_ip='10.0.0.10', dst_ip=target,
                           src_port=49152, dst_port=443, protocol=6,
                           packets=1, bytes=size, encrypted=True, transport='TLS')


def feature_snapshot(extractor, event, features):
    history = extractor.sources[str(event.src_ip)]
    return {'iat_mean_seconds': features['iat_mean'], 'iat_cv': features['iat_cv'],
            'peer_history_count': features['history_count'],
            'destination_count_last_10s': features['destination_count'],
            'source_destination_count_last_60s': len({str(item.dst_ip) for item in history}),
            'peer_persistence_last_60s': features['history_count'] / len(history),
            'source_history_count_last_60s': len(history)}


def verdict(positive, first_alert, total):
    early = first_alert is not None and first_alert['event'] < total
    return 'TP' if positive and early else 'FN' if positive else 'FP' if first_alert else 'TN'


def score(name, positive, kind, size):
    stream = list(events(kind, size))
    pipeline = Pipeline()
    audit_extractor = FeatureExtractor()
    first = final_features = None
    max_peer_history = 0
    for index, event in enumerate(stream, start=1):
        alerts = pipeline.process(event)
        features = audit_extractor.update(event)
        snap = feature_snapshot(audit_extractor, event, features)
        final_features = snap
        max_peer_history = max(max_peer_history, snap['peer_history_count'])
        for alert in alerts:
            if alert.threat_class == 'BOTNET_C2' and first is None:
                for key, value in [('iat_mean', features['iat_mean']),
                                   ('iat_cv', features['iat_cv']),
                                   ('history_count', features['history_count']),
                                   ('destination_count', features['destination_count'])]:
                    if abs(alert.raw_evidence_metrics[key] - value) > 1e-8:
                        raise AssertionError(f'Alert/runtime feature mismatch: {key}')
                first = {'event': index, 'timestamp': alert.timestamp,
                         'elapsed_seconds': (event.timestamp - stream[0].timestamp) / 1000,
                         'detection_source': alert.detection_source,
                         'evidence': alert.raw_evidence_metrics,
                         'audited_features': snap}
    digest = hashlib.sha256(json.dumps(
        [event.model_dump(mode='json') for event in stream],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'scenario': name, 'ground_truth_c2': positive,
            'events': len(stream), 'observed_duration_seconds':
            (stream[-1].timestamp - stream[0].timestamp) / 1000,
            'observed_stream_sha256': digest, 'verdict': verdict(positive, first, len(stream)),
            'first_alert': first, 'max_peer_history_count': max_peer_history,
            'final_audited_features': final_features}


def main():
    rows = [score(*case) for case in CASES]
    counts = {key: sum(row['verdict'] == key for row in rows)
              for key in ('TP', 'TN', 'FP', 'FN')}
    report = {'scope': 'Controlled synthetic development only; no reserved or production evaluation',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ('datasets/validate_c2_beacon.py',
                                             'detection/pipeline.py', 'features/extractor.py',
                                             'ml/artifact.json')},
              'counts': counts, 'scenarios': rows}
    (ROOT / 'ml/c2_beacon_development.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts,
                      'first_alerts': {row['scenario']: row['first_alert']['event']
                                       if row['first_alert'] else None for row in rows}}, indent=2))


if __name__ == '__main__':
    main()

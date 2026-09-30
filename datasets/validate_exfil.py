"""Offline controlled forward-volume audit; no traffic is transmitted."""
import hashlib
import json
from pathlib import Path

from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0


CASES = (
    ('large_one_way', True, 'single_large'),
    ('sustained_one_way', True, 'sustained'),
    ('sustained_observed_bidir', True, 'bidir'),
    ('volume_only_one_way', True, 'volume_only'),
    ('slow_sustained', True, 'slow'),
    ('cloud_backup', False, 'sustained'),
    ('legitimate_large_upload', False, 'single_large'),
    ('synchronization', False, 'bidir'),
    ('replication_deployment', False, 'volume_only'),
    ('ordinary_small_transfer', False, 'small'),
    ('inbound_heavy_transfer', False, 'inbound_heavy'),
)


def events(kind):
    count = 1 if kind == 'single_large' else 6 if kind == 'volume_only' else 8
    interval_ms = 15_000 if kind == 'slow' else 4_000 if kind == 'volume_only' else 5_000
    bytes_forward = (25_000_000 if kind == 'single_large' else
                     5_000_000 if kind == 'volume_only' else
                     1_000_000 if kind == 'small' else
                     2_000_000 if kind == 'inbound_heavy' else 4_000_000)
    reverse = (100_000 if kind == 'bidir' else
               8_000_000 if kind == 'inbound_heavy' else None)
    for index in range(count):
        yield TrafficEvent(timestamp=START + index * interval_ms,
                           src_ip='10.0.0.10', dst_ip='198.51.100.20',
                           src_port=49152, dst_port=443, protocol=6,
                           packets=100, bytes=bytes_forward,
                           reverse_observed=reverse is not None,
                           reverse_bytes=reverse,
                           encrypted=True, transport='TLS')


def reference(seen, event):
    history = [item for item in seen if item.src_ip == event.src_ip
               and item.timestamp >= event.timestamp - 60_000]
    recent = [item for item in seen if item.src_ip == event.src_ip
              and item.timestamp >= event.timestamp - 10_000]
    ratio = (event.bytes / event.reverse_bytes
             if event.reverse_observed and event.reverse_bytes else None)
    return {'observed_forward_bytes_60s': sum(item.bytes for item in history),
            'observed_forward_byte_rate_10s': sum(item.bytes for item in recent) / 10,
            'reverse_available': int(event.reverse_observed),
            'observed_byte_ratio': ratio,
            'ratio_status': ('reverse_unavailable' if not event.reverse_observed else
                             'zero_observed_reverse_bytes' if event.reverse_bytes == 0 else
                             'finite_observed_ratio')}


def verdict(positive, first, total):
    early = first is not None and (total == 1 or first['event'] < total)
    return 'TP' if positive and early else 'FN' if positive else 'FP' if first else 'TN'


def score(name, positive, kind):
    stream = list(events(kind))
    pipeline = Pipeline()
    seen = []
    first = final_reference = None
    for index, event in enumerate(stream, start=1):
        seen.append(event)
        current = reference(seen, event)
        final_reference = current
        for alert in pipeline.process(event):
            if alert.threat_class != 'DATA_EXFILTRATION' or first is not None:
                continue
            evidence = alert.raw_evidence_metrics
            if evidence['egress_bytes'] != current['observed_forward_bytes_60s']:
                raise AssertionError('Incorrect causal source-forward byte total')
            if evidence['reverse_available'] != current['reverse_available']:
                raise AssertionError('Reverse availability was fabricated')
            if evidence['observed_byte_ratio'] != current['observed_byte_ratio']:
                raise AssertionError('Observed byte ratio disagrees with reference')
            first = {'event': index, 'timestamp': alert.timestamp,
                     'elapsed_seconds': (event.timestamp - stream[0].timestamp) / 1000,
                     'detection_source': alert.detection_source,
                     'evidence': evidence, 'supporting_evidence': alert.supporting_evidence,
                     'independent_reference': current,
                     'runtime_byte_rate': pipeline.extractor.global_rates.bytes / 10}
    digest = hashlib.sha256(json.dumps(
        [event.model_dump(mode='json') for event in stream],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'scenario': name, 'ground_truth_exfil_like': positive,
            'events': len(stream), 'observed_stream_sha256': digest,
            'verdict': verdict(positive, first, len(stream)),
            'first_alert': first, 'final_reference': final_reference}


def high_flow_count_stress():
    """Separate accuracy check, excluded from scenario confusion counts."""
    pipeline = Pipeline()
    first = None
    for index in range(1000):
        event = TrafficEvent(timestamp=START + index * 50,
                             src_ip='10.0.0.10', dst_ip='198.51.100.20',
                             src_port=49152, dst_port=443, protocol=6,
                             packets=25, bytes=25_000)
        for alert in pipeline.process(event):
            if alert.threat_class == 'DATA_EXFILTRATION' and first is None:
                first = {'event': index + 1, 'evidence': alert.raw_evidence_metrics}
    return {'events': 1000, 'observed_forward_bytes': 25_000_000,
            'bounded_source_history_bytes': sum(item.bytes for item in pipeline.extractor.sources['10.0.0.10']),
            'first_alert': first}


def main():
    rows = [score(*case) for case in CASES]
    counts = {key: sum(row['verdict'] == key for row in rows)
              for key in ('TP', 'TN', 'FP', 'FN')}
    report = {'scope': 'Controlled synthetic development only; no reserved or production evaluation',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ('datasets/validate_exfil.py',
                                             'detection/pipeline.py', 'features/extractor.py',
                                             'ml/artifact.json')},
              'counts': counts, 'scenarios': rows,
              'high_flow_count_stress': high_flow_count_stress()}
    (ROOT / 'ml/exfil_development.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts,
                      'first_alerts': {row['scenario']: row['first_alert']['event']
                                       if row['first_alert'] else None for row in rows},
                      'high_flow_count_stress': report['high_flow_count_stress']}, indent=2))


if __name__ == '__main__':
    main()

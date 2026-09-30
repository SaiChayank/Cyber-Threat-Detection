"""Controlled offline reconnaissance replay; no packets or probes are sent."""
import hashlib
import json
from pathlib import Path

from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0


CASES = (
    ('vertical_scan', True, 'vertical', 100),
    ('horizontal_scan', True, 'horizontal', 100),
    ('mixed_scan', True, 'mixed', 100),
    ('slower_vertical_scan', True, 'vertical', 500),
    ('slow_horizontal_scan', True, 'horizontal', 2000),
    ('authorised_vulnerability_scanner', False, 'vertical', 100),
    ('authorised_asset_inventory', False, 'horizontal', 100),
    ('service_discovery', False, 'discovery', 100),
    ('scheduled_monitoring', False, 'monitoring', 2000),
    ('administrative_port_check', False, 'admin', 100),
    ('ordinary_browsing', False, 'browsing', 1000),
)


def events(kind, interval_ms):
    count = 9 if kind == 'admin' else 24 if kind == 'discovery' else 32
    for index in range(count):
        target = (f'198.51.100.{20 + index}' if kind in ('horizontal', 'discovery', 'monitoring')
                  else f'198.51.100.{20 + index % 16}' if kind == 'mixed'
                  else f'198.51.100.{20 + index % 3}' if kind == 'browsing'
                  else '198.51.100.20')
        port = (1000 + index if kind in ('vertical', 'mixed', 'admin')
                else 80 if kind == 'browsing' and index % 2 else 443)
        syn = kind not in ('monitoring', 'browsing')
        yield TrafficEvent(timestamp=START + index * interval_ms,
                           src_ip='10.0.0.10', dst_ip=target,
                           src_port=49152, dst_port=port, protocol=6,
                           packets=1, bytes=60, syn=syn,
                           syn_packets=int(syn))


def reference(seen, current):
    recent = [event for event in seen if event.timestamp >= current.timestamp - 10_000
              and event.src_ip == current.src_ip]
    return {'destination_count': len({str(event.dst_ip) for event in recent}),
            'port_count': len({event.dst_port for event in recent}),
            'syn_fraction': sum(event.syn for event in recent) / len(recent),
            'observed_event_rate': len(recent) / 10,
            'events_in_ten_seconds': len(recent)}


def verdict(positive, first, total):
    early = first is not None and first['event'] < total
    return 'TP' if positive and early else 'FN' if positive else 'FP' if first else 'TN'


def score(name, positive, kind, interval_ms):
    stream = list(events(kind, interval_ms))
    pipeline = Pipeline()
    seen = []
    first = None
    alert_count = 0
    max_hosts = max_ports = 0
    final_reference = None
    for index, event in enumerate(stream, start=1):
        seen.append(event)
        current = reference(seen, event)
        final_reference = current
        max_hosts = max(max_hosts, current['destination_count'])
        max_ports = max(max_ports, current['port_count'])
        for alert in pipeline.process(event):
            if alert.threat_class != 'RECONNAISSANCE':
                continue
            alert_count += 1
            if first is None:
                for field in ('destination_count', 'port_count', 'syn_fraction'):
                    if abs(alert.raw_evidence_metrics[field] - current[field]) > 1e-9:
                        raise AssertionError(f'Non-causal or incorrect {field} evidence')
                first = {'event': index, 'timestamp': alert.timestamp,
                         'elapsed_seconds': (event.timestamp - stream[0].timestamp) / 1000,
                         'detection_source': alert.detection_source,
                         'evidence': alert.raw_evidence_metrics,
                         'independent_reference': current}
    digest = hashlib.sha256(json.dumps(
        [event.model_dump(mode='json') for event in stream],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'scenario': name, 'ground_truth_unauthorised_scan': positive,
            'events': len(stream), 'observed_stream_sha256': digest,
            'verdict': verdict(positive, first, len(stream)),
            'first_alert': first, 'alert_count': alert_count,
            'max_destination_hosts_ten_seconds': max_hosts,
            'max_destination_ports_ten_seconds': max_ports,
            'final_reference': final_reference}


def main():
    rows = [score(*case) for case in CASES]
    counts = {key: sum(row['verdict'] == key for row in rows)
              for key in ('TP', 'TN', 'FP', 'FN')}
    report = {'scope': 'Controlled synthetic development only; no reserved or production evaluation',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ('datasets/validate_recon.py',
                                             'detection/pipeline.py', 'features/extractor.py',
                                             'ml/artifact.json')},
              'counts': counts, 'scenarios': rows}
    (ROOT / 'ml/recon_development.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts,
                      'first_alerts': {row['scenario']: row['first_alert']['event']
                                       if row['first_alert'] else None for row in rows}}, indent=2))


if __name__ == '__main__':
    main()

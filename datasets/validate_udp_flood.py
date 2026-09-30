"""Offline, labelled UDP development replays; no packets are transmitted."""
from collections import Counter
import hashlib
import ipaddress
import json
import math
import struct
from pathlib import Path

from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0
VICTIM = '198.51.100.10'
DNS_QUESTION = (struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0) +
                b'\x03www\x07example\x04test\x00' + struct.pack('!HH', 1, 1))


def frame(source, target, size, port, dns=False):
    payload_length = size - 28
    question = DNS_QUESTION if dns else b''
    assert payload_length >= len(question)
    payload = question + bytes(payload_length - len(question))
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, size, 1, 0, 64, 17, 0,
                     ipaddress.IPv4Address(source).packed,
                     ipaddress.IPv4Address(target).packed)
    udp = struct.pack('!HHHH', 49152, port, size - 20, 0)
    return ethernet + ip + udp + payload


def raw_events(kind):
    parser = ProtocolParser()
    for index in range(12_000):
        source, target, size, port, dns = '10.1.0.1', VICTIM, 64, 9000, False
        if kind == 'flood_many_large':
            source, size = f'10.1.0.{index % 32 + 1}', 1200
        elif kind == 'benign_quic_bulk':
            size, port = 1200, 443
        elif kind == 'benign_dns_queries':
            source, size, port, dns = f'10.1.0.{index % 32 + 1}', 80, 53, True
        packet = frame(source, target, size, port, dns)
        flow, dns_record, tls = parser.parse_packet(packet, (START + index * .5) / 1000)
        assert flow is not None
        if dns:
            assert dns_record is not None
        yield from_packet(flow, dns_record, tls)


def aggregate_events(kind):
    if kind == 'benign_spread':
        for index in range(20):
            yield TrafficEvent(timestamp=START + index * 100, src_ip='10.1.0.1',
                               dst_ip=f'198.51.100.{index + 10}', protocol=17,
                               src_port=49152, dst_port=5004,
                               packets=800, bytes=800 * 1200)
        return
    if kind in ('flood_many_mixed', 'benign_telemetry_many'):
        for index in range(32):
            size = (64, 512, 1200)[index % 3] if kind == 'flood_many_mixed' else 256
            yield TrafficEvent(timestamp=START + index * 100,
                               src_ip=f'10.1.0.{index + 1}', dst_ip=VICTIM,
                               protocol=17, src_port=49152, dst_port=9000 if kind == 'flood_many_mixed' else 8125,
                               packets=400, bytes=400 * size)
        return
    packets = 4000 if kind != 'benign_dns_low' else 100
    size = 1200 if kind != 'benign_dns_low' else 80
    count = 4 if kind != 'benign_dns_low' else 10
    for index in range(count):
        yield TrafficEvent(timestamp=START + index * 1000, src_ip='10.1.0.1',
                           dst_ip=VICTIM, protocol=17, src_port=49152,
                           dst_port=9000 if kind == 'flood_single_large' else 5004,
                           packets=packets, bytes=packets * size)


CASES = (
    ('flood_single_small', True, 'raw'),
    ('flood_many_large', True, 'raw'),
    ('flood_single_large', True, 'aggregate'),
    ('flood_many_mixed', True, 'aggregate'),
    ('benign_quic_bulk', False, 'raw'),
    ('benign_dns_queries', False, 'raw'),
    ('benign_video_bulk', False, 'aggregate'),
    ('benign_spread', False, 'aggregate'),
    ('benign_dns_low', False, 'aggregate'),
    ('benign_telemetry_many', False, 'aggregate'),
)


def score(kind, positive, format_name):
    pipeline = Pipeline()
    events = list(raw_events(kind) if format_name == 'raw' else aggregate_events(kind))
    first = None
    for index, event in enumerate(events, start=1):
        for alert in pipeline.process(event):
            if alert.threat_class == 'DDOS' and first is None:
                first = {'event': index, 'timestamp': alert.timestamp,
                         'evidence': alert.raw_evidence_metrics,
                         'supporting_evidence': alert.supporting_evidence}
    target = [event for event in events if str(event.dst_ip) == VICTIM]
    packets = sum(event.packets for event in target)
    sizes = [event.bytes / event.packets for event in target]
    weights = [event.packets for event in target]
    mean = sum(size * count for size, count in zip(sizes, weights)) / packets if packets else 0
    variance = sum(count * (size - mean) ** 2 for size, count in zip(sizes, weights)) / packets if packets else 0
    source_counts = Counter()
    for event in target:
        source_counts[str(event.src_ip)] += event.packets
    entropy = -sum(count / packets * math.log2(count / packets)
                   for count in source_counts.values()) if packets else 0
    detected_early = first is not None and first['event'] < len(events)
    verdict = 'TP' if positive and detected_early else 'FN' if positive else 'FP' if first else 'TN'
    return {'scenario': kind, 'positive': positive, 'format': format_name,
            'events': len(events), 'verdict': verdict, 'first_alert': first,
            'observed': {'target_packet_rate': packets / 10,
                         'target_byte_rate': sum(event.bytes for event in target) / 10,
                         'source_count': len(source_counts), 'source_entropy': entropy,
                         'destination_concentration': packets / sum(event.packets for event in events),
                         'packet_size_mean': mean,
                         'packet_size_cv': math.sqrt(variance) / mean if mean else 0,
                         'packet_size_basis': 'packet_exact' if format_name == 'raw' else 'summary_mean_proxy'}}


def main():
    rows = [score(*case) for case in CASES]
    counts = {key: sum(row['verdict'] == key for row in rows) for key in ('TP', 'TN', 'FP', 'FN')}
    report = {'scope': 'Inspected synthetic development cases only; not reserved or production quality',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ('datasets/validate_udp_flood.py', 'detection/pipeline.py',
                                             'features/extractor.py', 'features/rate_window.py',
                                             'ingest/protocol_parsers.py', 'ingest/metadata.py')},
              'counts': counts, 'scenarios': rows}
    (ROOT / 'ml/udp_flood_development.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts, 'first_alerts': {row['scenario']:
                      row['first_alert']['event'] if row['first_alert'] else None for row in rows}}, indent=2))


if __name__ == '__main__':
    main()

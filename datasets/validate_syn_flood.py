"""One deterministic, offline SYN-flood controlled evaluation; never sends traffic."""
import hashlib
import ipaddress
import json
import math
import struct
from pathlib import Path

from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from replay.scenarios import scenario
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0
TARGET = '198.51.100.10'
OTHER = '198.51.100.11'
SYN, ACK, PSH_ACK = 0x02, 0x10, 0x18


def raw_frame(source, target, flags):
    source_bytes = ipaddress.IPv4Address(source).packed
    target_bytes = ipaddress.IPv4Address(target).packed
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0,
                     source_bytes, target_bytes)
    tcp = struct.pack('!HHIIHHHH', 49152, 443, 1, 0,
                      (5 << 12) | flags, 65535, 0, 0)
    return ethernet + ip + tcp


def raw_events(kind):
    parser = ProtocolParser()
    total = 14_000 if kind in ('raw_mixed', 'raw_cross') else 12_000
    for index in range(total):
        source, target, flags = '10.1.0.1', TARGET, SYN
        if kind == 'raw_diverse':
            source = f'10.1.0.{index % 32 + 1}'
        elif kind == 'raw_mixed' and index % 7 == 6:
            source, target, flags = '10.2.0.1', OTHER, ACK
        elif kind == 'raw_ack':
            flags = ACK
        elif kind == 'raw_pshack':
            flags = PSH_ACK
        elif kind == 'raw_small_syn':
            flags = SYN if index % 20 == 0 else ACK
        elif kind == 'raw_cross':
            if index % 7 == 6:
                source, target, flags = '10.1.0.1', TARGET, SYN
            else:
                source, target, flags = '10.2.0.1', OTHER, ACK
        packet = raw_frame(source, target, flags)
        flow, dns, tls = parser.parse_packet(packet, (START + index * .5) / 1000)
        assert flow is not None and dns is None and tls is None
        yield from_packet(flow)


def aggregate_events(kind):
    if kind == 'agg_existing':
        yield from scenario('DDOS', seed=100)
        return
    if kind == 'agg_diverse':
        for index in range(32):
            yield TrafficEvent(timestamp=START + index * 100, src_ip=f'10.1.0.{index + 1}',
                               dst_ip=TARGET, protocol=6, dst_port=443,
                               packets=400, bytes=24_000, syn=True, syn_packets=400)
        return
    if kind == 'handshake':
        for index in range(120):
            yield TrafficEvent(timestamp=START + index * 100, src_ip='10.1.0.1',
                               dst_ip=TARGET, protocol=6, dst_port=443,
                               packets=1, bytes=60, syn=index % 3 == 0,
                               syn_packets=int(index % 3 == 0))
        return
    for index in range(4):
        yield TrafficEvent(timestamp=START + index * 1000, src_ip='10.1.0.1',
                           dst_ip=TARGET, protocol=6, dst_port=443,
                           packets=4000, bytes=240_000, syn=kind == 'agg_single',
                           syn_packets=4000 if kind == 'agg_single' else 0)


CASES = (
    ('raw_single', True, 'packet'),
    ('raw_diverse', True, 'packet'),
    ('raw_mixed', True, 'packet'),
    ('agg_single', True, 'summary'),
    ('agg_diverse', True, 'summary'),
    ('agg_existing', True, 'summary'),
    ('raw_ack', False, 'packet'),
    ('raw_pshack', False, 'packet'),
    ('raw_small_syn', False, 'packet'),
    ('raw_cross', False, 'packet'),
    ('agg_established', False, 'summary'),
    ('handshake', False, 'summary'),
)


def assess(kind, positive, format_name):
    pipeline = Pipeline()
    stream = raw_events(kind) if format_name == 'packet' else aggregate_events(kind)
    first_alert = None
    count = target_packets = threshold_event = 0
    last_timestamp = None
    for count, event in enumerate(stream, start=1):
        if str(event.dst_ip) == (TARGET if kind != 'agg_existing' else '198.51.100.20'):
            target_packets += event.packets
            if threshold_event == 0 and target_packets >= 10_000:
                threshold_event = count
        for alert in pipeline.process(event):
            if alert.threat_class == 'DDOS' and first_alert is None:
                first_alert = {'event': count, 'timestamp': alert.timestamp,
                               'evidence': alert.raw_evidence_metrics,
                               'detection_source': str(alert.detection_source)}
        last_timestamp = event.timestamp
    target = TARGET if kind != 'agg_existing' else '198.51.100.20'
    window = pipeline.extractor.syn_targets.get(target)
    final_entropy = (math.log2(window.observations) -
                     window.count_log_sum / window.observations) if window and window.observations else 0
    detected_early = first_alert is not None and first_alert['event'] < count
    verdict = 'TP' if positive and detected_early else 'FN' if positive else 'FP' if first_alert else 'TN'
    return {'scenario': kind, 'positive': positive, 'format': format_name,
            'events': count, 'target_packets': target_packets,
            'threshold_event': threshold_event or None,
            'first_alert': first_alert, 'last_timestamp': last_timestamp,
            'final_target_packet_rate': window.packets / 10 if window else 0,
            'final_target_syn_fraction': window.syn_packets / window.packets if window and window.packets else 0,
            'final_target_fraction_basis': ('summary_flag_proxy' if window.summary_events else 'packet_exact') if window else None,
            'final_target_source_entropy': final_entropy,
            'final_target_source_count_lower_bound': len(window.sources) if window else 0,
            'final_target_entropy_partial': bool(window.sources.get(None)) if window else False,
            'verdict': verdict}


def main():
    rows = [assess(*case) for case in CASES]
    counts = {key: sum(row['verdict'] == key for row in rows) for key in ('TP', 'TN', 'FP', 'FN')}
    tp, tn, fp, fn = (counts[key] for key in ('TP', 'TN', 'FP', 'FN'))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    early = all(row['first_alert'] and row['first_alert']['event'] <= row['threshold_event']
                for row in rows if row['positive'])
    by_name = {row['scenario']: row for row in rows}
    feature_gate = (
        all(by_name[name]['final_target_packet_rate'] == 1200 and
            by_name[name]['final_target_syn_fraction'] == 1 and
            by_name[name]['final_target_fraction_basis'] == 'packet_exact' and
            not by_name[name]['final_target_entropy_partial']
            for name in ('raw_single', 'raw_diverse', 'raw_mixed')) and
        abs(by_name['raw_single']['final_target_source_entropy']) < 1e-9 and
        abs(by_name['raw_mixed']['final_target_source_entropy']) < 1e-9 and
        abs(by_name['raw_diverse']['final_target_source_entropy'] - 5) < 1e-9 and
        by_name['raw_diverse']['final_target_source_count_lower_bound'] == 32 and
        all(by_name[name]['final_target_syn_fraction'] == 0
            for name in ('raw_ack', 'raw_pshack')) and
        abs(by_name['raw_small_syn']['final_target_syn_fraction'] - .05) < 1e-9 and
        by_name['raw_cross']['final_target_packet_rate'] == 200 and
        all(row['first_alert'] and
            row['first_alert']['evidence']['rate_window_resolution_ms'] == 1000 and
            row['first_alert']['evidence']['syn_fraction_basis'] ==
            ('packet_exact' if row['format'] == 'packet' else 'declared_summary_counts')
            for row in rows if row['positive'])
    )
    gate = counts == {'TP': 6, 'TN': 6, 'FP': 0, 'FN': 0} and early and feature_gate
    report = {
        'scope': 'Deterministic, labelled offline TCP-only controlled replays; not field accuracy',
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ('datasets/validate_syn_flood.py', 'features/rate_window.py',
                                       'features/extractor.py', 'detection/pipeline.py',
                                       'ingest/protocol_parsers.py', 'ingest/metadata.py',
                                       'replay/scenarios.py')},
        'counts': counts, 'precision': precision, 'recall': recall, 'f1': f1,
        'fpr': fpr, 'incremental_gate_passed': early,
        'feature_gate_passed': feature_gate,
        'controlled_gate_passed': gate, 'scenarios': rows,
    }
    output = ROOT / 'ml/syn_flood_validation.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': counts, 'precision': precision, 'recall': recall,
                      'f1': f1, 'fpr': fpr, 'incremental_gate_passed': early,
                      'feature_gate_passed': feature_gate,
                      'controlled_gate_passed': gate}, indent=2))


if __name__ == '__main__':
    main()

"""Verify one frozen TQH development cell's raw TLS/session-label association.

No classification, TrafficEvent generation, model loading, replay or persistence.
Publisher topology establishes controlled lab intent; addresses are join metadata.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path

from datasets.qualify_tls_capture import (capture_header, complete_clienthello,
    raw_packets, sha256, tcp_metadata)
from ingest.pcap_reader import validate_header
from ingest.protocol_parsers import ProtocolParser


def rows(path):
    with Path(path).open(encoding='utf-8') as handle:
        return [json.loads(line, parse_float=Decimal) for line in handle if line.strip()]


def unique_uids(records):
    result = {}
    for record in records:
        uid = record['uid']
        if uid in result:
            raise ValueError('Duplicate source UID')
        result[uid] = record
    return result


def epoch_ns(value):
    number = Decimal(str(value))
    if not number.is_finite() or number < 0:
        raise ValueError('Invalid source timestamp/duration')
    return int(number * 1_000_000_000)


def iso_ns(value):
    seconds, fraction = divmod(value, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'


def manifest_ns(value):
    timestamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ValueError('Source manifest must specify UTC')
    delta = timestamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def flow_tuple(record, label=False):
    names = ('orig_h', 'resp_h', 'orig_p', 'resp_p') if label else (
        'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p')
    return (record[names[0]], record[names[1]],
            int(record[names[2]]) if record.get(names[2]) is not None else None,
            int(record[names[3]]) if record.get(names[3]) is not None else None,
            record['proto'])


def same_json_number(left, right):
    # JSON re-export uses binary64 numbers. Different shortest decimal spellings
    # can denote exactly the same binary64 value; no numeric tolerance is used.
    # Missing/null duration remains unavailable, never converted to zero.
    if left is None or right is None:
        return left is None and right is None
    return math.isfinite(float(left)) and math.isfinite(float(right)) and float(left) == float(right)


def label_errors(label, connection, manifest):
    errors = []
    if (flow_tuple(label, True) != flow_tuple(connection) or
            not same_json_number(label['ts'], connection['ts']) or
            not same_json_number(label.get('duration'), connection.get('duration'))):
        errors.append('label/connection tuple or time disagrees')
    if label['capture_id'] != manifest['capture_id']:
        errors.append('capture identity disagrees')
    topology, intent = manifest['topology'], label['label']
    origin, destination = label['orig_h'], label['resp_h']
    if intent == 'malicious_c2':
        if origin not in topology['victims'] or destination not in topology['c2']:
            errors.append('C2 label contradicts publisher topology')
    elif intent == 'benign':
        if (origin not in topology['victims'] + topology['benign_gen'] or
                destination.startswith(topology['internal_prefix'])):
            errors.append('benign label contradicts publisher topology')
    else:
        errors.append('intent outside this selected acquisition scope')
    return errors


def qualify(pcap, label_directory):
    directory = Path(label_directory)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    publisher_gate = json.loads((directory / 'gate.json').read_text(encoding='utf-8'))
    labelled = unique_uids(rows(directory / 'labeled.jsonl'))
    connections = unique_uids(rows(directory / 'conn.log'))
    ssl = defaultdict(list)
    for record in rows(directory / 'ssl.log'):
        ssl[record['uid']].append(record)
    issues, windows = [], defaultdict(list)
    for uid, label in labelled.items():
        if uid not in connections:
            issues.append({'uid': uid, 'errors': ['unmatched connection UID']})
            continue
        errors = label_errors(label, connections[uid], manifest)
        if errors:
            issues.append({'uid': uid, 'errors': errors})
            continue
        if label['proto'] == 'tcp':
            if label.get('duration') is None:
                continue  # No fabricated end time for an unavailable duration.
            start = epoch_ns(label['ts'])
            end = start + epoch_ns(label['duration'])
            windows[flow_tuple(label, True)].append((uid, start, end))
    start_utc, end_utc = manifest_ns(manifest['start_utc']), manifest_ns(manifest['end_utc'])
    if end_utc < start_utc:
        raise ValueError('Reversed source run window')
    parser = ProtocolParser()
    counts, observations, sessions = Counter(), [], {}
    seen_packets = set()
    counts['exact_frame_timestamp_duplicates'] = 0
    first, last, previous = None, None, None
    with Path(pcap).open('rb') as handle:
        header = handle.read(24)
        validate_header(header)  # Original runtime format must pass; no conversion.
        endian, scale, snaplen, linktype, _ = capture_header(header)
        for index, timestamp, frame, original in raw_packets(handle, endian, scale, snaplen):
            counts['packets'] += 1
            packet_key = (timestamp, hashlib.sha256(frame).digest())
            counts['exact_frame_timestamp_duplicates'] += packet_key in seen_packets
            seen_packets.add(packet_key)  # Diagnose only; preserve packet order and indices.
            counts['clipped_packets'] += len(frame) < original
            counts['out_of_order_packets'] += previous is not None and timestamp < previous
            previous = timestamp
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            flow, _, tls = parser.parse_packet(frame, timestamp / 1_000_000_000)
            if flow is None:
                counts['runtime_unparsed_packets'] += 1
                continue
            counts['runtime_ip_packets'] += 1
            if tls is None:
                continue
            counts['native_clienthello_sidecars'] += 1
            tcp = tcp_metadata(frame, linktype)
            if tcp is None or not complete_clienthello(tcp[3]):
                counts['hello_outside_verified_ipv4_single_record_scope'] += 1
                continue
            key = (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 'tcp')
            candidates = [(uid, start) for uid, start, end in windows.get(key, [])
                          if start - 1000 <= timestamp <= end + 1000]
            observation = {'packet_index': index, 'timestamp_ns': timestamp,
                           'timestamp_utc': iso_ns(timestamp), 'tuple': list(key),
                           'ja3': tls.ja3_hash, 'offered_legacy_version': tls.tls_version,
                           'cipher_count': len(tls.cipher_suites),
                           'extension_count': tls.extension_count,
                           'matching_uids': [uid for uid, _ in candidates]}
            observations.append(observation)
            if len(candidates) != 1:
                counts['unmatched_or_ambiguous_clienthellos'] += 1
                continue
            uid, connection_start = candidates[0]
            source_ja3 = {record.get('ja3') for record in ssl[uid] if record.get('ja3')}
            if not start_utc <= timestamp <= end_utc or tls.ja3_hash not in source_ja3:
                counts['clock_or_source_ja3_mismatch'] += 1
                continue
            if uid in sessions:
                counts['additional_hello_observations_same_uid'] += 1
                continue
            sessions[uid] = dict(observation, uid=uid, label=labelled[uid]['label'],
                milliseconds_after_connection_start=(timestamp - connection_start) / 1_000_000,
                source_ssl_ja3_match=True)
    distribution = Counter(record['label'] for record in sessions.values())
    gates = {'original_runtime_format': True, 'source_label_uid_tuple_time_integrity': not issues,
             'raw_packet_clock_inside_explicit_utc_run': first is not None and start_utc <= first <= last <= end_utc,
             'complete_native_labelled_c2_clienthello': distribution['malicious_c2'] > 0,
             'complete_native_labelled_benign_clienthello': distribution['benign'] > 0}
    return {'role': 'development-only', 'scope': 'One controlled Merlin HTTP/2-TLS cell; acquisition only',
            'qualified': all(gates.values()), 'qualification_gates': gates,
            'pcap': str(pcap), 'pcap_sha256': sha256(pcap), 'linktype': linktype, 'snaplen': snaplen,
            'capture_id': manifest['capture_id'], 'source_run_utc': [manifest['start_utc'], manifest['end_utc']],
            'raw_first_last_utc': [iso_ns(first), iso_ns(last)] if first is not None else [],
            'label_rows': len(labelled), 'connection_rows': len(connections),
            'source_label_counts': dict(Counter(r['label'] for r in labelled.values())),
            'unlabelled_connection_uids': len(set(connections) - set(labelled)),
            'label_integrity_issues': issues, 'packet_counts': dict(counts),
            'qualified_session_counts': dict(distribution), 'qualified_sessions': list(sessions.values()),
            'clienthello_observations': observations,
            'publisher_gate_mode': publisher_gate.get('mode'),
            'publisher_failed_checks': {name: value for name, value in publisher_gate.get('checks', {}).items()
                                        if value.get('pass') is False},
            'training_performed': False, 'prediction_performed': False,
            'promotion_performed': False, 'encrypted_model_training_status': 'BLOCKED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    if manifest['role'] != 'development-only' or args.output.exists():
        raise ValueError('Requires frozen development inputs and a new output')
    for artifact in manifest['artifacts']:
        if sha256(artifact['file']) != artifact['sha256']:
            raise ValueError('Input artifact hash mismatch')
    result = qualify(manifest['pcap'], manifest['labels'])
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({key: result[key] for key in ('qualified', 'qualification_gates',
        'label_rows', 'source_label_counts', 'packet_counts', 'qualified_session_counts')}))


if __name__ == '__main__':
    main()

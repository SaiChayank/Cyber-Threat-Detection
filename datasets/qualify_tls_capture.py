"""Read-only qualification of explicitly selected development TLS captures.

Linux-cooked decoding below is diagnostic only. It never creates Ethernet
frames, TrafficEvents, labels or alerts; the runtime reader's format decision is
reported independently. No TCP reassembly, payload decryption or model is used.
"""
import argparse
import csv
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

from ingest.pcap_reader import validate_header
from ingest.protocol_parsers import ProtocolParser


MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1000),
    b'\xa1\xb2\xc3\xd4': ('>', 1000),
    b'\x4d\x3c\xb2\xa1': ('<', 1),
    b'\xa1\xb2\x3c\x4d': ('>', 1),
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def capture_header(header):
    if len(header) != 24 or header[:4] not in MAGICS:
        raise ValueError('Requires a complete classic PCAP header')
    endian, fraction_ns = MAGICS[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHiIII', header[4:])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 16 * 1024 * 1024:
        raise ValueError('Invalid classic PCAP header')
    try:
        validate_header(header)
        runtime_error = None
    except ValueError as exc:
        runtime_error = str(exc)
    return endian, fraction_ns, snaplen, linktype, runtime_error


def raw_packets(handle, endian, fraction_ns, snaplen, limit=None):
    index = 0
    while limit is None or index < limit:
        header = handle.read(16)
        if not header:
            return
        if len(header) != 16:
            raise ValueError('Truncated PCAP packet header')
        seconds, fraction, size, original = struct.unpack(endian + 'IIII', header)
        if size > snaplen or size > original or size > 16 * 1024 * 1024:
            raise ValueError('Invalid PCAP packet length')
        if fraction >= 1_000_000_000 // fraction_ns:
            raise ValueError('Invalid PCAP fractional timestamp')
        frame = handle.read(size)
        if len(frame) != size:
            raise ValueError('Truncated PCAP packet')
        index += 1
        yield index, seconds * 1_000_000_000 + fraction * fraction_ns, frame, original


def tcp_metadata(frame, linktype):
    """Inspect complete IPv4/TCP bytes in Ethernet or SLL; never synthesize bytes."""
    if linktype == 113 and len(frame) >= 16:
        kind, offset = struct.unpack_from('!H', frame, 14)[0], 16
    elif linktype == 1 and len(frame) >= 14:
        kind, offset = struct.unpack_from('!H', frame, 12)[0], 14
        if kind == 0x8100 and len(frame) >= 18:
            kind, offset = struct.unpack_from('!H', frame, 16)[0], 18
    else:
        return None
    if kind != 0x0800 or len(frame) < offset + 20:
        return None
    ihl = (frame[offset] & 15) * 4
    length = struct.unpack_from('!H', frame, offset + 2)[0]
    fragment = struct.unpack_from('!H', frame, offset + 6)[0]
    end, tcp = offset + length, offset + ihl
    if (frame[offset] >> 4 != 4 or ihl < 20 or length < ihl + 20 or
            end > len(frame) or fragment & 0x3fff or frame[offset + 9] != 6):
        return None
    tcp_length = (frame[tcp + 12] >> 4) * 4
    if tcp_length < 20 or tcp + tcp_length > end:
        return None
    src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
    dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
    sport, dport, sequence = struct.unpack_from('!HHI', frame, tcp)
    return (src, dst, sport, dport, 6), sequence, length, frame[tcp + tcp_length:end]


def complete_clienthello(payload):
    """A complete first ClientHello in one observed record/packet is required."""
    if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
        return False
    record_length = struct.unpack_from('!H', payload, 3)[0]
    handshake_length = int.from_bytes(payload[6:9], 'big')
    return (record_length >= 4 + handshake_length >= 40 and
            len(payload) >= 5 + record_length)


def csv_window(row, utc_offset_seconds):
    # Publisher export truncates to seconds and omits the local UTC offset.
    value = datetime.strptime(row['TimeStamp'], '%Y-%m-%d %H:%M:%S')
    start = int(value.replace(tzinfo=timezone.utc).timestamp()) - utc_offset_seconds
    duration = Decimal(row['Duration'])
    if not duration.is_finite() or duration < 0:
        raise ValueError('Invalid labelled duration')
    start_ns = start * 1_000_000_000
    return start_ns, start_ns + int(duration * 1_000_000_000) + 1_000_000_000


def csv_tuple(row):
    return (row['SourceIP'], row['DestinationIP'], int(row['SourcePort']),
            int(row['DestinationPort']), 6)


def inspect_selected(pcap, annotation, inferred_offset_seconds=-10800):
    parser, hellos, packet_times = ProtocolParser(), [], {}
    counts = {'packets': 0, 'clipped_packets': 0, 'out_of_order_packets': 0,
              'complete_ipv4_tcp_packets': 0}
    first, last, previous = None, None, None
    with Path(pcap).open('rb') as handle:
        header = handle.read(24)
        endian, fraction_ns, snaplen, linktype, runtime_error = capture_header(header)
        for index, timestamp_ns, frame, original in raw_packets(handle, endian, fraction_ns, snaplen):
            counts['packets'] += 1
            counts['clipped_packets'] += int(len(frame) < original)
            counts['out_of_order_packets'] += int(previous is not None and timestamp_ns < previous)
            previous = timestamp_ns
            first = timestamp_ns if first is None else min(first, timestamp_ns)
            last = timestamp_ns if last is None else max(last, timestamp_ns)
            tcp = tcp_metadata(frame, linktype)
            if tcp is None:
                continue
            key, sequence, ip_bytes, payload = tcp
            counts['complete_ipv4_tcp_packets'] += 1
            packet_times.setdefault(key, []).append(timestamp_ns)
            if complete_clienthello(payload):
                record_end = 5 + struct.unpack_from('!H', payload, 3)[0]
                sidecar = parser._try_parse_tls_client_hello(payload[:record_end], 'source-qualification-only', ip_bytes)
                if sidecar is not None:
                    hellos.append({'packet_index': index, 'timestamp_ns': timestamp_ns,
                                   'tuple': list(key), 'tcp_sequence': sequence,
                                   'observed_ip_bytes': ip_bytes, 'ja3': sidecar.ja3_hash,
                                   'cipher_count': len(sidecar.cipher_suites),
                                   'extension_count': sidecar.extension_count})
    with Path(annotation).open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        rows, columns = list(reader), reader.fieldnames
    matches = []
    for row in rows:
        key, seen = csv_tuple(row), packet_times.get(csv_tuple(row), [])
        zero_start, zero_end = csv_window(row, 0)
        start, end = csv_window(row, inferred_offset_seconds)
        matches.append({'tuple': list(key), 'doh_field': row.get('DoH'),
                        'csv_naive_start': row['TimeStamp'], 'duration_s': float(row['Duration']),
                        'tuple_seen': bool(seen),
                        'packets_in_window_as_if_csv_utc': sum(zero_start <= t < zero_end for t in seen),
                        'packets_in_window_with_inferred_offset': sum(start <= t < end for t in seen),
                        'clienthellos_in_window_with_inferred_offset': [h['packet_index'] for h in hellos
                            if tuple(h['tuple']) == key and start <= h['timestamp_ns'] < end]})
    return {'pcap': str(pcap), 'pcap_bytes': Path(pcap).stat().st_size,
            'pcap_sha256': sha256(pcap), 'annotation': str(annotation),
            'annotation_sha256': sha256(annotation), 'linktype': linktype, 'snaplen': snaplen,
            'runtime_capture_accepted': runtime_error is None, 'runtime_rejection': runtime_error,
            'counts': counts, 'first_timestamp_ns': first, 'last_timestamp_ns': last,
            'clienthello_observations': hellos, 'annotation_columns': columns,
            'annotation_rows': len(rows), 'candidate_tuple_time_joins': matches,
            'csv_utc_offset_seconds_tested': inferred_offset_seconds,
            'csv_utc_offset_independently_verified': False,
            'explicit_malicious_session_labels_verified': False,
            'qualified_for_current_runtime': False}


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--manifest', type=Path, required=True)
    args.add_argument('--output', type=Path, required=True)
    options = args.parse_args()
    manifest = json.loads(options.manifest.read_text(encoding='utf-8'))
    if manifest['role'] != 'development-only' or options.output.exists():
        raise ValueError('Requires development-only inputs and a new output file')
    for entry in manifest['selected_captures']:
        for path, expected in ((entry['pcap'], entry['pcap_sha256']),
                               (entry['annotation'], entry['annotation_sha256'])):
            if sha256(path) != expected:
                raise ValueError(f'Selected artifact hash mismatch: {path}')
    result = {'scope': 'Raw source qualification only; no fitting, prediction, replay or alerts',
              'role': manifest['role'], 'qualified_for_current_runtime': False,
              'captures': [inspect_selected(entry['pcap'], entry['annotation'])
                           for entry in manifest['selected_captures']]}
    options.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"Inspected {len(result['captures'])} fixed development captures; runtime qualification fails.")


if __name__ == '__main__':
    main()

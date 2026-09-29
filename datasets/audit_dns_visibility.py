"""Read-only DNS/LLMNR visibility inventory for the downloaded classic PCAPs."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import struct

from ingest.protocol_parsers import ProtocolParser
from ingest.pcap_reader import validate_header


def frames(path):
    with path.open('rb') as handle:
        header = handle.read(24)
        snaplen = validate_header(header)
        magic = header[:4]
        endian = '>' if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d') else '<'
        while packet_header := handle.read(16):
            if len(packet_header) != 16:
                raise ValueError('Truncated packet header')
            _, _, size, original = struct.unpack(endian + 'IIII', packet_header)
            if size > snaplen or size > original:
                raise ValueError('Invalid packet size')
            packet = handle.read(size)
            if len(packet) != size:
                raise ValueError('Truncated packet')
            yield packet, original


def transport(frame, allow_truncated=False):
    """Return transport tuple; optionally expose clipped UDP payload for audit."""
    if len(frame) < 14:
        return None
    kind = struct.unpack_from('!H', frame, 12)[0]
    offset = 14
    if kind == 0x8100 and len(frame) >= 18:
        kind = struct.unpack_from('!H', frame, 16)[0]
        offset = 18
    if kind == 0x0800 and len(frame) >= offset + 20:
        ihl = (frame[offset] & 15) * 4
        if frame[offset] >> 4 != 4 or ihl < 20 or len(frame) < offset + ihl:
            return None
        length = struct.unpack_from('!H', frame, offset + 2)[0]
        fragment = struct.unpack_from('!H', frame, offset + 6)[0]
        if fragment & 0x3fff:
            return None
        protocol = frame[offset + 9]
        src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
        end = min(len(frame), offset + length)
        offset += ihl
    elif kind == 0x86dd and len(frame) >= offset + 40:
        protocol = frame[offset + 6]
        src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
        dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
        end = min(len(frame), offset + 40 + struct.unpack_from('!H', frame, offset + 4)[0])
        offset += 40
    else:
        return None
    if protocol not in (6, 17) or end < offset + (20 if protocol == 6 else 8):
        return None
    src_port, dst_port = struct.unpack_from('!HH', frame, offset)
    if protocol == 17:
        udp_len = struct.unpack_from('!H', frame, offset + 4)[0]
        complete = udp_len >= 8 and offset + udp_len <= end
        if not complete and not allow_truncated:
            return None
        payload = frame[offset + 8:min(end, offset + max(udp_len, 8))]
    else:
        header_len = (frame[offset + 12] >> 4) * 4
        if header_len < 20 or offset + header_len > end:
            return None
        payload = frame[offset + header_len:end]
        complete = True  # TCP message completeness is assessed by wire_dns.
    result = (protocol, src_port, dst_port, src, dst, payload)
    return result + (complete,) if allow_truncated else result


def wire_dns(payload, tcp=False, questions_only=False):
    """Read question and answer *metadata*; never decode answer content."""
    if tcp:
        if len(payload) < 2:
            return None
        length = struct.unpack_from('!H', payload)[0]
        if len(payload) < length + 2:
            return None
        payload = payload[2:length + 2]
    if len(payload) < 12:
        return None
    _, flags, qd, an, _, _ = struct.unpack_from('!HHHHHH', payload)
    if qd > 20 or an > 100:
        return None
    offset, questions, answers = 12, [], []
    try:
        for _ in range(qd):
            name, offset = ProtocolParser._read_dns_name(payload, offset)
            if offset + 4 > len(payload):
                return None
            qtype, _ = struct.unpack_from('!HH', payload, offset)
            questions.append((name.lower(), qtype))
            offset += 4
        for _ in range(0 if questions_only else an):
            _, offset = ProtocolParser._read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return None
            rtype, _, _, rdlength = struct.unpack_from('!HHIH', payload, offset)
            offset += 10 + rdlength
            if offset > len(payload):
                return None
            answers.append(rtype)
    except (ValueError, UnicodeDecodeError, struct.error):
        return None
    return {'response': bool(flags & 0x8000), 'questions': questions,
            'answers': answers, 'bytes': len(payload)}


def entropy(value):
    counts = Counter(value.lower())
    size = len(value)
    return -sum((n / size) * math.log2(n / size) for n in counts.values()) if size else 0.0


def distribution(values):
    if not values:
        return {'count': 0}
    values.sort()
    return {'count': len(values), 'min': values[0], 'p50': values[len(values) // 2],
            'p95': values[int((len(values) - 1) * .95)],
            'p99': values[int((len(values) - 1) * .99)], 'max': values[-1]}


def inspect(path):
    with path.open('rb') as capture:
        snaplen = validate_header(capture.read(24))
    counts, protocol_ports, dns_types, answers, llmnr_types = (Counter() for _ in range(5))
    dns_names, llmnr_names, llmnr_destinations = Counter(), Counter(), Counter()
    truncated_dns_sources, truncated_dns_destinations = Counter(), Counter()
    truncated_dns_first_label_lengths, truncated_dns_udp_lengths = Counter(), Counter()
    truncated_dns_label_pairs = Counter()
    truncated_dns_second_prefix_entropies = []
    truncated_dns_prefixes = Counter()
    name_lengths, first_lengths, label_counts, name_entropies, first_entropies = ([] for _ in range(5))
    llmnr_examples = []
    parser = ProtocolParser()
    for frame, original in frames(path):
        counts['frames'] += 1
        if len(frame) < original:
            counts['capture_truncated_frames'] += 1
        packet = transport(frame, allow_truncated=True)
        if packet is None:
            counts['unsupported_or_non_transport'] += 1
            continue
        proto, src_port, dst_port, src, dst, payload, complete = packet
        if complete:
            counts['transport_packets'] += 1
        else:
            counts['udp_declared_length_exceeds_capture'] += 1
        service = 53 if 53 in (src_port, dst_port) else 5355 if 5355 in (src_port, dst_port) else None
        if service is None:
            continue
        protocol_ports[f'{"tcp" if proto == 6 else "udp"}/{service}'] += 1
        if not complete:
            counts[f'port_{service}_truncated_udp'] += 1
            partial = wire_dns(payload, questions_only=True)
            if partial is not None and partial['questions']:
                counts[f'port_{service}_recoverable_first_question_only'] += 1
            if service == 53 and len(payload) >= 12:
                flags, qd = struct.unpack_from('!HH', payload, 2)
                counts['truncated_dns_response_header' if flags & 0x8000 else 'truncated_dns_query_header'] += 1
                if partial is not None and partial['questions']:
                    counts['truncated_dns_response_question_complete' if flags & 0x8000
                           else 'truncated_dns_query_question_complete'] += 1
                if qd and len(payload) >= 13:
                    first_length = payload[12]
                    truncated_dns_first_label_lengths[str(first_length)] += 1
                    truncated_dns_udp_lengths[str(len(payload))] += 1
                    truncated_dns_sources[src] += 1
                    truncated_dns_destinations[dst] += 1
                    prefix = payload[13:13 + min(first_length, 20)]
                    if prefix and all(33 <= b <= 126 for b in prefix):
                        truncated_dns_prefixes[prefix.decode('ascii')] += 1
                    second_offset = 13 + first_length
                    if not flags & 0x8000 and first_length < 64 and second_offset < len(payload):
                        second_length = payload[second_offset]
                        if 0 < second_length < 64:
                            truncated_dns_label_pairs[f'{first_length},{second_length}'] += 1
                            visible = payload[second_offset + 1:second_offset + 1 + second_length]
                            if visible and all(33 <= b <= 126 for b in visible):
                                truncated_dns_second_prefix_entropies.append(round(entropy(visible.decode('ascii')), 3))
                            if len(visible) < second_length:
                                counts['truncated_dns_second_label_incomplete'] += 1
            continue
        if service == 5355:
            llmnr_destinations[dst] += 1
        wire = wire_dns(payload, tcp=proto == 6)
        if wire is None:
            counts[f'port_{service}_unparseable_or_incomplete'] += 1
            continue
        counts[f'port_{service}_wire_parseable'] += 1
        if service == 5355:
            counts['llmnr_responses' if wire['response'] else 'llmnr_queries'] += 1
            for name, qtype in wire['questions']:
                llmnr_names[name] += 1
                llmnr_types[str(qtype)] += 1
                if len(llmnr_examples) < 5 and name not in llmnr_examples:
                    llmnr_examples.append(name)
            continue
        counts['dns_responses' if wire['response'] else 'dns_queries'] += 1
        for rtype in wire['answers']:
            answers[str(rtype)] += 1
        if wire['response']:
            continue
        for name, qtype in wire['questions']:
            dns_names[name] += 1
            dns_types[str(qtype)] += 1
            labels = name.split('.')
            name_lengths.append(len(name))
            first_lengths.append(len(labels[0]))
            label_counts.append(len(labels))
            name_entropies.append(round(entropy(name), 3))
            first_entropies.append(round(entropy(labels[0]), 3))
        _, parsed_dns, _ = parser.parse_packet(frame, 0)
        if parsed_dns is not None:
            counts['dns_query_runtime_sidecars'] += 1
    return {'file': str(path), 'bytes': path.stat().st_size, 'snaplen': snaplen,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'counts': dict(counts), 'port_packets': dict(protocol_ports),
            'dns_query_types': dict(dns_types), 'dns_answer_types': dict(answers),
            'dns_unique_query_names': len(dns_names), 'dns_top_names': dns_names.most_common(6),
            'dns_name_length': distribution(name_lengths), 'dns_first_label_length': distribution(first_lengths),
            'dns_label_count': distribution(label_counts),
            'dns_name_entropy': distribution(name_entropies),
            'dns_first_label_entropy': distribution(first_entropies),
            'dns_queries_with_first_label_ge_50': sum(n >= 50 for n in first_lengths),
            'llmnr_question_types': dict(llmnr_types),
            'llmnr_unique_question_names': len(llmnr_names),
            'llmnr_top_names': llmnr_names.most_common(6),
            'llmnr_destinations': llmnr_destinations.most_common(6),
            'llmnr_examples': llmnr_examples,
            'truncated_dns_first_label_lengths': dict(truncated_dns_first_label_lengths),
            'truncated_dns_first_second_label_lengths': dict(truncated_dns_label_pairs),
            'truncated_dns_second_label_visible_prefix_entropy': distribution(truncated_dns_second_prefix_entropies),
            'truncated_dns_payload_bytes': dict(truncated_dns_udp_lengths),
            'truncated_dns_top_sources': truncated_dns_sources.most_common(6),
            'truncated_dns_top_destinations': truncated_dns_destinations.most_common(6),
            'truncated_dns_top_prefixes': truncated_dns_prefixes.most_common(6)}


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('paths', nargs='+', type=Path)
    args.add_argument('--output', type=Path)
    parsed = args.parse_args()
    result = {'scope': 'Read-only metadata inventory; capture category is not per-packet truth',
              'captures': [inspect(path) for path in parsed.paths]}
    body = json.dumps(result, indent=2)
    if parsed.output:
        parsed.output.write_text(body + '\n', encoding='utf-8')
    else:
        print(body)


if __name__ == '__main__':
    main()

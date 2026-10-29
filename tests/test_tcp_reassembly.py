"""Bounded in-order TCP reassembly of TLS records and DNS/TCP messages. Framing only, no decryption."""
import socket
import struct

import pytest

from ingest.metadata import from_packet
from ingest.protocol_parsers import MAX_STREAMS, MAX_STREAM_BYTES, ProtocolParser

CLIENT, SERVER = '10.0.0.5', '203.0.113.9'
NOW = 1_700_000_000.0


def ext(kind, body=b''):
    return struct.pack('!HH', kind, len(body)) + body


def client_hello(padding=0, hostname=b'api.example.org'):
    sni_name = b'\x00' + struct.pack('!H', len(hostname)) + hostname
    extensions = (ext(0, struct.pack('!H', len(sni_name)) + sni_name) + ext(10, struct.pack('!HHH', 4, 29, 23))
                  + ext(11, b'\x01\x00') + (ext(21, b'\x00' * padding) if padding else b''))
    hello = (struct.pack('!H', 771) + b'\x00' * 32 + b'\x00' + struct.pack('!H', 4) + struct.pack('!HH', 49195, 49199)
             + b'\x01\x00' + struct.pack('!H', len(extensions)) + extensions)
    handshake = b'\x01' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake


def dns_query(name='www.example.org'):
    labels = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    message = struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)
    return struct.pack('!H', len(message)) + message


def frame(payload, seq, sport=50000, dport=443, flags=0x18, src=CLIENT, dst=SERVER):
    tcp = struct.pack('!HHIIHHHH', sport, dport, seq & 0xFFFFFFFF, 1, (5 << 12) | flags, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b'\x00' * 12 + b'\x08\x00' + ip + tcp


def feed(parser, segments, start=1000, step=0.01, **kwargs):
    """Parse consecutive in-order segments of one stream; return the sidecar tuples."""
    results, seq = [], start
    for index, segment in enumerate(segments):
        flow, dns, tls = parser.parse_packet(frame(segment, seq, **kwargs), NOW + index * step)
        results.append((flow, dns, tls))
        seq += len(segment)
    return results


def split(data, *sizes):
    parts, pos = [], 0
    for size in sizes:
        parts.append(data[pos:pos + size])
        pos += size
    parts.append(data[pos:])
    return [p for p in parts if p]


def test_split_client_hello_matches_unsplit_and_emits_only_on_the_last_segment():
    hello = client_hello(padding=2000)
    whole = ProtocolParser().parse_packet(frame(hello, 1000), NOW)[2]
    results = feed(ProtocolParser(), split(hello, 1000, 700))
    assert [r[2] is not None for r in results] == [False, False, True]
    tls = results[-1][2]
    assert tls.ja3_hash == whole.ja3_hash and tls.ja4 == whole.ja4 and tls.sni == 'api.example.org'
    assert from_packet(results[-1][0], tls=tls).tls_ja4 == whole.ja4


def test_split_dns_over_tcp_message_is_reassembled():
    query = dns_query('long-label-x' * 3 + '.example.org')
    results = feed(ProtocolParser(), split(query, 10), dport=53)
    assert results[0][1] is None
    assert results[1][1].query_name == 'long-label-x' * 3 + '.example.org'


def test_unsplit_messages_and_unrelated_payloads_are_unchanged():
    parser = ProtocolParser()
    assert parser.parse_packet(frame(client_hello(), 1000), NOW)[2] is not None
    assert parser.parse_packet(frame(dns_query(), 1000, dport=53), NOW)[1].query_name == 'www.example.org'
    assert parser.parse_packet(frame(b'GET / HTTP/1.1\r\n', 1000, dport=80), NOW)[2] is None
    assert not parser.streams


def test_retransmitted_segment_is_ignored_and_message_still_completes():
    hello = client_hello(padding=2000)
    first, second = split(hello, 1000)
    parser = ProtocolParser()
    parser.parse_packet(frame(first, 1000), NOW)
    assert parser.parse_packet(frame(first, 1000), NOW + .01)[2] is None  # Retransmission.
    assert parser.parse_packet(frame(second, 1000 + len(first)), NOW + .02)[2] is not None


def test_gap_or_reordering_abandons_the_buffer_without_guessing():
    hello = client_hello(padding=3000)
    first, second, third = split(hello, 1000, 1000)
    parser = ProtocolParser()
    parser.parse_packet(frame(first, 1000), NOW)
    assert parser.parse_packet(frame(third, 1000 + len(first) + len(second)), NOW + .01)[2] is None
    assert not parser.streams
    assert parser.parse_packet(frame(second, 1000 + len(first)), NOW + .02)[2] is None


def test_idle_fin_and_rst_streams_are_dropped():
    hello = client_hello(padding=2000)
    first, second = split(hello, 1000)
    parser = ProtocolParser()
    parser.parse_packet(frame(first, 1000), NOW)
    assert parser.parse_packet(frame(second, 1000 + len(first)), NOW + 11)[2] is None  # Idle > 10 s.
    parser.parse_packet(frame(first, 5000), NOW)
    parser.parse_packet(frame(b'', 5000 + len(first), flags=0x14), NOW + .01)  # RST.
    assert not parser.streams


def test_buffer_is_bounded_by_stream_count_and_record_size():
    parser = ProtocolParser()
    for port in range(40000, 40000 + MAX_STREAMS + 50):
        parser.parse_packet(frame(client_hello(padding=2000)[:900], 1000, sport=port), NOW)
    assert len(parser.streams) == MAX_STREAMS
    oversized = b'\x16\x03\x03' + struct.pack('!H', MAX_STREAM_BYTES + 100) + b'\x00' * 500
    parser = ProtocolParser()
    parser.parse_packet(frame(oversized, 1000), NOW)
    assert not parser.streams


def test_sequence_numbers_wrap_around():
    hello = client_hello(padding=2000)
    first, second = split(hello, 1000)
    start = 0xFFFFFFFF - 300
    results = feed(ProtocolParser(), [first, second], start=start)
    assert results[-1][2] is not None

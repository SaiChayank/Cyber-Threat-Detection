"""JA3S/JA4 extraction, encrypted-session features and detection paths. Metadata only."""
import hashlib
import struct

import pytest

from detection.pipeline import Pipeline
from features.tls_session import TlsSessionState
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from schemas.tls_metadata import TLSMetadataRecord
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0
GREASE = 0x1A1A


def ext(kind, body=b''):
    return struct.pack('!HH', kind, len(body)) + body


def u16s(values):
    return b''.join(struct.pack('!H', v) for v in values)


def client_hello(ciphers, extensions, version=0x0303):
    body = b''.join(extensions)
    hello = (struct.pack('!H', version) + b'\x00' * 32 + b'\x00' +
             struct.pack('!H', 2 * len(ciphers)) + u16s(ciphers) + b'\x01\x00' +
             struct.pack('!H', len(body)) + body)
    handshake = b'\x01' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake


def server_hello(cipher, extensions, version=0x0303):
    body = b''.join(extensions)
    hello = (struct.pack('!H', version) + b'\x00' * 32 + b'\x00' + struct.pack('!H', cipher) +
             b'\x00' + struct.pack('!H', len(body)) + body)
    handshake = b'\x02' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x03' + struct.pack('!H', len(handshake)) + handshake


def reference_hello(alpn=b'h2'):
    """Cipher/extension/signature lists of the published JA4 example t13d1516h2_8daaf6152771_e5627efa2ab1."""
    ciphers = [GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
               0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    sni = b'\x00\x0e\x00\x00\x0bexample.com'
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    extensions = [ext(GREASE), ext(0x0000, sni), ext(0x0017), ext(0xFF01, b'\x00'),
                  ext(0x000A, b'\x00\x02\x00\x1d'), ext(0x000B, b'\x01\x00'), ext(0x0023),
                  ext(0x0010, struct.pack('!H', len(alpn) + 1) + bytes([len(alpn)]) + alpn),
                  ext(0x0005, b'\x01\x00\x00\x00\x00'), ext(0x000D, struct.pack('!H', 16) + u16s(sigs)),
                  ext(0x0012), ext(0x0033, b'\x00\x00'), ext(0x002D, b'\x01\x01'),
                  ext(0x002B, b'\x06' + u16s([GREASE, 0x0304, 0x0303])), ext(0x001B, b'\x02\x00\x02'),
                  ext(0x4469, b'\x00\x00'), ext(0x0015, b'\x00\x00')]
    return client_hello(ciphers, extensions)


def test_ja4_matches_published_reference_and_ignores_grease():
    tls = ProtocolParser()._try_parse_tls_client_hello(reference_hello(), 'flow', 600)
    assert tls.ja4 == 't13d1516h2_8daaf6152771_e5627efa2ab1'
    assert tls.sni == 'example.com'


def test_ja4_uses_hex_when_alpn_edges_are_not_alphanumeric():
    tls = ProtocolParser()._try_parse_tls_client_hello(reference_hello(alpn=b'\xab\x01'), 'flow', 600)
    assert tls.ja4.split('_')[0] == 't13d1516a1'


def test_ja4_without_extensions_or_ciphers_uses_zero_hashes():
    ja4 = TLSMetadataRecord.generate_ja4('t', 0x0301, [], [], [], False, None, [])
    assert ja4 == 't10i000000_000000000000_000000000000'


def test_server_hello_exposes_ja3s_only():
    record = server_hello(0xC02F, [ext(0xFF01, b'\x00'), ext(0x000B, b'\x01\x00'), ext(0x0023), ext(GREASE)])
    parser = ProtocolParser()
    assert parser._try_parse_tls_client_hello(record, 'flow', len(record)) is None
    tls = parser._try_parse_tls_server_hello(record, 'flow', len(record))
    assert tls.role == 'server'
    assert tls.ja3s_string == '771,49199,65281-11-35'
    assert tls.ja3s_hash == hashlib.md5(b'771,49199,65281-11-35').hexdigest()
    assert tls.ja3_hash == '' and tls.ja4 is None


def test_truncated_server_hello_is_ignored():
    record = server_hello(0xC02F, [ext(0x000B, b'\x01\x00')])
    assert ProtocolParser()._try_parse_tls_server_hello(record[:30], 'flow', 30) is None


def frame(payload, src, dst, sport, dport):
    tcp = struct.pack('!HHIIHHHH', sport, dport, 1, 1, (5 << 12) | 0x18, 65535, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    return b'\x00' * 12 + b'\x08\x00' + ip + tcp + payload


def test_packet_path_carries_ja4_and_ja3s_into_events():
    parser = ProtocolParser()
    hello = parser.parse_packet(frame(reference_hello(), '10.0.0.5', '203.0.113.7', 50000, 443), 1_700_000_000.0)
    reply = parser.parse_packet(frame(server_hello(0x1301, [ext(0x002B, b'\x03\x04')]),
                                      '203.0.113.7', '10.0.0.5', 443, 50000), 1_700_000_000.1)
    client_event, server_event = from_packet(*hello), from_packet(*reply)
    assert client_event.tls_ja4 == 't13d1516h2_8daaf6152771_e5627efa2ab1'
    assert client_event.tls_fingerprint and client_event.tls_server_fingerprint is None
    assert server_event.tls_server_fingerprint == hashlib.md5(b'771,4865,43').hexdigest()
    assert server_event.tls_fingerprint is None and server_event.tls_ja4 is None
    assert server_event.encrypted and server_event.transport == 'TLS'


def event(offset_ms, src, dst, sport=50000, dport=443, size=150, **tls):
    return TrafficEvent(timestamp=START + offset_ms, src_ip=src, dst_ip=dst, src_port=sport,
                        dst_port=dport, protocol=6, bytes=size, encrypted=True, transport='TLS', **tls)


def test_session_joins_both_directions_and_measures_regularity():
    state = TlsSessionState()
    state.update(event(0, '10.0.0.5', '203.0.113.7', tls_ja4='t13d_a_b', tls_fingerprint='ja3'))
    state.update(event(50, '203.0.113.7', '10.0.0.5', 443, 50000, tls_server_fingerprint='ja3s'))
    for index in range(1, 6):
        features = state.update(event(5000 * index, '10.0.0.5', '203.0.113.7'))
    assert (features['tls_ja3'], features['tls_ja3s'], features['tls_ja4']) == ('ja3', 'ja3s', 't13d_a_b')
    assert features['tls_session_packets'] == 7
    assert features['tls_session_size_cv'] == 0 and features['tls_session_small_fraction'] == 1
    assert features['tls_fingerprint_clients'] == 1 and features['tls_client_population'] == 1
    restarted = state.update(event(5000 * 5 + 61000, '10.0.0.5', '203.0.113.7'))
    assert restarted['tls_session_packets'] == 1 and restarted['tls_ja4'] is None


def test_unencrypted_events_have_empty_session_features():
    state = TlsSessionState()
    plain = TrafficEvent(timestamp=START, src_ip='10.0.0.5', dst_ip='203.0.113.7', dst_port=80)
    assert state.update(plain)['tls_session_packets'] == 0 and not state.sessions


def run(pipeline, events):
    return [alert for e in events for alert in pipeline.process(e)]


def tls_alerts(alerts):
    return [a for a in alerts if a.threat_class == 'ENCRYPTED_MALWARE'
            and 'tls_basis' in a.raw_evidence_metrics]


@pytest.mark.parametrize('kind, fields', [
    ('ja4', dict(tls_ja4='t13d1516h2_8daaf6152771_e5627efa2ab1')),
    ('ja3s', dict(tls_server_fingerprint='0123456789abcdef0123456789abcdef')),
])
def test_listed_handshake_fingerprint_raises_indicator_alert(kind, fields):
    pipeline = Pipeline()
    value = next(iter(fields.values()))
    pipeline.tls_indicators[kind][value] = 'lab capture of a test family'
    first = (event(0, '203.0.113.7', '10.0.0.5', 443, 50000, **fields) if kind == 'ja3s'
             else event(0, '10.0.0.5', '203.0.113.7', **fields))
    alerts = tls_alerts(run(pipeline, [first, event(1000, '10.0.0.5', '203.0.113.7')]))
    assert alerts and alerts[0].timestamp == START  # Raised on the first listed handshake.
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['tls_basis'] == f'indicator_{kind}'
    assert evidence['tls_indicator_note'] == 'lab capture of a test family'
    assert evidence[f'tls_{kind}'] == value
    assert 'payload not decrypted' in alerts[0].supporting_evidence


def population():
    return [event(index * 10, f'10.0.0.{index + 1}', '203.0.113.10', tls_ja4='t13_common')
            for index in range(5)]


def regular_session(client, fingerprint, start, interval_ms=5000, sizes=None):
    sizes = sizes or [150] * 10
    return [event(start + index * interval_ms, client, '203.0.113.50', size=sizes[index],
                  **(dict(tls_ja4=fingerprint) if index == 0 else {}))
            for index in range(len(sizes))]


def test_rare_fingerprint_with_regular_small_packets_raises_behaviour_alert():
    alerts = tls_alerts(run(Pipeline(), population() + regular_session('10.0.0.9', 't13_rare', 1000)))
    assert len(alerts) == 1
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['tls_basis'] == 'rare_fingerprint_regular_session'
    assert evidence['tls_fingerprint_clients'] == 1 and evidence['tls_client_population'] >= 5
    assert evidence['tls_session_packets'] >= 8


def test_common_fingerprint_or_irregular_session_does_not_raise_behaviour_alert():
    common = population() + regular_session('10.0.0.9', 't13_common', 1000)
    assert tls_alerts(run(Pipeline(), common)) == []
    bursty = [150, 1400, 90, 1200, 300, 1500, 60, 900, 1300, 200]
    irregular = population() + regular_session('10.0.0.9', 't13_rare', 1000, sizes=bursty)
    assert tls_alerts(run(Pipeline(), irregular)) == []


def test_rarity_needs_minimum_client_population():
    assert tls_alerts(run(Pipeline(), regular_session('10.0.0.9', 't13_rare', 0))) == []


def test_failed_persistence_leaves_tls_state_unchanged():
    pipeline = Pipeline()
    run(pipeline, population())
    before = (dict(pipeline.extractor.tls.fingerprint_clients), list(pipeline.extractor.tls.sessions))

    def fail(alerts):
        raise OSError('disk full')
    with pytest.raises(OSError):
        pipeline.process(event(100, '10.0.0.9', '203.0.113.50', tls_ja4='t13_new'), persist=fail)
    assert (dict(pipeline.extractor.tls.fingerprint_clients), list(pipeline.extractor.tls.sessions)) == before

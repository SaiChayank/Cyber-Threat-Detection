"""QUIC Initial header fingerprint: unencrypted long-header fields only, never decrypted."""
import socket
import struct

import pytest

from detection.pipeline import Pipeline
from features.tls_session import TlsSessionState
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def initial(version=1, dcid=b'\x01' * 8, scid=b'', token=b'', size=1252, first=0xC0):
    header = bytes([first]) + struct.pack('!I', version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    header += bytes([len(token)]) + token
    return header + b'\xaa' * (size - len(header))  # Opaque protected payload; never interpreted.


def frame(payload, sport=50000, dport=443):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton('10.0.0.5'), socket.inet_aton('203.0.113.9'))
    return b'\x00' * 12 + b'\x08\x00' + ip + udp


def fingerprint(payload, **kwargs):
    flow, _, _ = ProtocolParser().parse_packet(frame(payload, **kwargs), 1_700_000_000.0)
    return flow.quic_fingerprint


def test_initial_long_header_is_fingerprinted_from_clear_fields():
    assert fingerprint(initial()) == 'q00000001.d8.s0.t0.l1252'
    assert fingerprint(initial(dcid=b'\x02' * 16, scid=b'\x03' * 4, token=b'tok', size=1350)) == 'q00000001.d16.s4.t1.l1350'


@pytest.mark.parametrize('payload', [
    initial(first=0x40),                 # Short header.
    initial(first=0xE0),                 # 0-RTT type, not Initial.
    initial(version=0),                  # Version negotiation.
    initial(dcid=b'\x01' * 21),          # Connection ID above the 20-byte limit.
    b'\xc0\x00\x00\x00\x01',             # Truncated.
    b'plain udp payload on port 443',
])
def test_non_initial_or_malformed_payloads_give_no_fingerprint(payload):
    assert fingerprint(payload) is None


def test_only_port_443_is_considered_and_event_carries_it_when_present():
    assert fingerprint(initial(), sport=50000, dport=8443) is None
    flow, _, _ = ProtocolParser().parse_packet(frame(initial()), 1_700_000_000.0)
    event = from_packet(flow)
    assert event.quic_fingerprint == 'q00000001.d8.s0.t0.l1252' and event.transport == 'QUIC' and event.encrypted
    assert 'quic_fingerprint' not in TrafficEvent(timestamp=1, src_ip='10.0.0.1', dst_ip='10.0.0.2').model_dump()


def quic_event(offset_ms, client, quic=None, size=150):
    return TrafficEvent(timestamp=START + offset_ms, src_ip=client, dst_ip='203.0.113.50', src_port=50000,
                        dst_port=443, protocol=17, bytes=size, encrypted=True, transport='QUIC',
                        quic_fingerprint=quic)


def test_session_and_rarity_use_the_quic_fingerprint():
    state = TlsSessionState()
    for index in range(5):
        state.update(quic_event(index * 10, f'10.0.0.{index + 1}', 'q00000001.d8.s0.t0.l1252'))
    features = state.update(quic_event(100, '10.0.0.9', 'q00000001.d0.s8.t0.l1200'))
    assert features['tls_quic'] == 'q00000001.d0.s8.t0.l1200'
    assert features['tls_fingerprint_clients'] == 1 and features['tls_client_population'] == 6


def test_listed_quic_fingerprint_raises_indicator_alert_without_decryption():
    pipeline = Pipeline()
    value = 'q00000001.d0.s8.t0.l1200'
    pipeline.tls_indicators['quic'][value] = 'lab QUIC stack'
    alerts = [a for e in [quic_event(0, '10.0.0.9', value), quic_event(500, '10.0.0.9')]
              for a in pipeline.process(e) if a.threat_class == 'ENCRYPTED_MALWARE']
    assert alerts and alerts[0].raw_evidence_metrics['tls_basis'] == 'indicator_quic'
    assert alerts[0].raw_evidence_metrics['tls_quic'] == value

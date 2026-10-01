"""Exact passive encrypted-metadata visibility regressions."""
import struct

from datasets.validate_encrypted import CASES, events
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from schemas.flow_record import FlowRecord
from schemas.tls_metadata import TLSMetadataRecord


def test_complete_tls_client_hello_exposes_ja3_and_sidecar_only():
    hostname = b'api.example.org'
    sni_name = b'\x00' + struct.pack('!H', len(hostname)) + hostname
    sni = struct.pack('!H', len(sni_name)) + sni_name
    extensions = (struct.pack('!HH', 0, len(sni)) + sni +
                  struct.pack('!HHH', 10, 6, 4) + struct.pack('!HH', 29, 23) +
                  struct.pack('!HH', 11, 2) + b'\x01\x00')
    hello = (struct.pack('!H', 771) + b'\x00' * 32 + b'\x00' +
             struct.pack('!H', 4) + struct.pack('!HH', 49195, 49199) +
             b'\x01\x00' + struct.pack('!H', len(extensions)) + extensions)
    handshake = b'\x01' + len(hello).to_bytes(3, 'big') + hello
    record = b'\x16\x03\x03' + struct.pack('!H', len(handshake)) + handshake
    tls = ProtocolParser()._try_parse_tls_client_hello(record, 'flow', len(record))
    assert isinstance(tls, TLSMetadataRecord)
    assert tls.ja3_string == '771,49195-49199,0-10-11,29-23,0'
    assert tls.extension_count == 3
    assert tls.cipher_suites == [49195, 49199]
    assert tls.sni == 'api.example.org'
    assert tls.ja4 is None
    assert tls.is_quic is False

    flow = FlowRecord(flow_id='flow', src_ip='192.0.2.1', dst_ip='198.51.100.2',
                      src_port=49152, dst_port=443, protocol=6,
                      timestamp_start=1_700_000_000_000.0,
                      timestamp_end=1_700_000_000_000.0,
                      packets_forward=1, packets_backward=0,
                      bytes_forward=len(record), bytes_backward=0,
                      tcp_flags_forward=0, is_unidirectional=True)
    event = from_packet(flow, tls=tls)
    assert event.tls_fingerprint == tls.ja3_hash
    assert event.transport == 'TLS'
    assert not hasattr(event, 'cipher_suites')
    assert not hasattr(event, 'extension_count')


def test_port_443_quic_inference_does_not_fabricate_handshake_fingerprint():
    flow = FlowRecord(flow_id='quic', src_ip='192.0.2.1', dst_ip='198.51.100.2',
                      src_port=49152, dst_port=443, protocol=17,
                      timestamp_start=1_700_000_000_000.0,
                      timestamp_end=1_700_000_000_000.0,
                      packets_forward=1, packets_backward=0,
                      bytes_forward=1200, bytes_backward=0,
                      tcp_flags_forward=0, is_unidirectional=True)
    event = from_packet(flow)
    assert event.transport == 'QUIC'
    assert event.encrypted is True
    assert event.tls_fingerprint is None


def test_controlled_validation_groups_and_handshake_observations_are_disjoint():
    assert len({case[2] for case in CASES}) == len(CASES)
    assert {case[3] for case in CASES} == {'TLS', 'QUIC', 'IP'}
    starts = []
    for index, case in enumerate(CASES):
        stream = list(events(case, index))
        starts.append(stream[0].timestamp)
        assert all(left.timestamp < right.timestamp for left, right in zip(stream, stream[1:]))
        assert all(event.tls_fingerprint is None for event in stream[1:])
        assert stream[0].tls_fingerprint == case[4]
    assert all(left < right for left, right in zip(starts, starts[1:]))

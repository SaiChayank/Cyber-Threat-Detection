"""
Unit and Integration Tests for Canonical Schemas and Protocol Parsers
"""

import struct
from pathlib import Path
import pytest

from schemas.enums import ThreatClass, Severity, DetectorType
from schemas.flow_record import FlowRecord
from schemas.dns_record import DNSRecord
from schemas.tls_metadata import TLSMetadataRecord
from schemas.alert import AlertEvent
from ingest.dead_letter import DeadLetterQueue
from ingest.protocol_parsers import ProtocolParser
from ingest.pcap_reader import PcapReader


def test_flow_record_unidirectional_invariants():
    """Verify FlowRecord maintains zero return-path properties safely"""
    fid = FlowRecord.compute_flow_id("10.0.0.1", "192.168.1.1", 12345, 80, 6, 1700000000.0)
    assert len(fid) == 32
    
    flow = FlowRecord(
        flow_id=fid,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=12345,
        dst_port=80,
        protocol=6,
        timestamp_start=1700000000.0,
        timestamp_end=1700005000.0,
        packets_forward=10,
        packets_backward=0,
        bytes_forward=1500,
        bytes_backward=0,
        tcp_flags_forward=0x02,  # SYN
        is_unidirectional=True
    )
    assert flow.is_unidirectional is True
    assert flow.packets_backward == 0
    assert flow.bytes_backward == 0
    assert flow.duration_seconds == 5.0
    assert flow.total_bytes == 1500


def test_dns_record_normalization():
    """Verify DNSRecord FQDN stripping and lowercase normalization"""
    dns = DNSRecord.from_query(
        query_id=101,
        flow_id="test_flow_123",
        query_name="X92KMZ01.Corp-Auth.COM.",
        query_type=16,  # TXT
        src_ip="10.0.0.2",
        dst_ip="8.8.8.8",
        timestamp=1700000000.0
    )
    assert dns.query_name == "x92kmz01.corp-auth.com"
    assert dns.query_length == len("x92kmz01.corp-auth.com")
    assert dns.query_type == 16


def test_ja3_fingerprint_generation():
    """Verify RFC-compliant JA3 string & MD5 hash generation with GREASE filtering"""
    ssl_ver = 771  # TLS 1.2
    ciphers = [0x0A0A, 49195, 49199]  # 0x0A0A is GREASE
    extensions = [0, 23, 0x1A1A, 65281]  # 0x1A1A is GREASE
    curves = [29, 23, 24]
    points = [0]

    ja3_str, ja3_hash = TLSMetadataRecord.generate_ja3(
        ssl_ver, ciphers, extensions, curves, points
    )
    # GREASE values (0x0A0A and 0x1A1A) must be excluded
    assert ja3_str == "771,49195-49199,0-23-65281,29-23-24,0"
    assert len(ja3_hash) == 32


def test_alert_event_standardization():
    """Verify AlertEvent satisfies NTRO/SIH schema contract"""
    alert = AlertEvent.create(
        flow_id="flow_abcdef",
        threat_class=ThreatClass.BOTNET_C2,
        confidence_score=0.8923,
        severity=Severity.HIGH,
        supporting_evidence="Periodic beaconing detected with low CV = 0.038",
        src_ip="10.100.0.15",
        dst_ip="198.51.100.4",
        src_port=49152,
        dst_port=443,
        protocol=6,
        detection_source=DetectorType.ML
    )
    d = alert.to_dict()
    assert d["threat_class"] == "BOTNET_C2"
    assert d["confidence_score"] == 0.892
    assert d["severity"] == "HIGH"
    assert "supporting_evidence" in d
    assert d["detection_source"] == "ML"


def test_protocol_parser_tcp_syn():
    """Verify zero-copy parser extracts synthetic TCP SYN frame correctly"""
    # Build synthetic Ethernet + IPv4 + TCP SYN frame
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    tcp_hdr = struct.pack("!HHIIHHHH", 50000, 80, 1000, 0, (5 << 12) | 0x02, 65535, 0, 0)
    raw_packet = eth_hdr + ip_hdr + tcp_hdr

    parser = ProtocolParser()
    flow, dns, tls = parser.parse_packet(raw_packet, 1700000000.0)

    assert flow is not None
    assert flow.src_ip == "10.0.0.1"
    assert flow.dst_ip == "10.0.0.2"
    assert flow.src_port == 50000
    assert flow.dst_port == 80
    assert flow.protocol == 6
    assert flow.tcp_flags_forward == 0x02  # SYN


def test_dead_letter_on_malformed_packets():
    """Verify malformed frames are logged to DLQ without crashing parser"""
    dlq = DeadLetterQueue()
    parser = ProtocolParser(dlq)

    # 1. Truncated frame
    flow, dns, tls = parser.parse_packet(b"\x00\x01\x02", 1700000000.0)
    assert flow is None
    assert dlq.corrupt_packet_count == 1

    # 2. Corrupt IP header (IHL < 20)
    corrupt_frame = b"\x00" * 12 + b"\x08\x00" + b"\x41\x00\x00\x28" + b"\x00" * 20
    flow, dns, tls = parser.parse_packet(corrupt_frame, 1700000000.0)
    assert flow is None
    assert dlq.corrupt_packet_count == 2


def test_pcap_reader_streaming(tmp_path: Path):
    """Verify PcapReader parses standard PCAP file end-to-end"""
    pcap_file = tmp_path / "test_stream.pcap"

    # Write valid PCAP header + 2 packets
    global_hdr = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet LinkType 1
    eth_hdr = b"\x00" * 12 + b"\x08\x00"
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\n\x00\x00\x05", b"\n\x00\x00\x06")
    tcp_hdr = struct.pack("!HHIIHHHH", 4433, 8080, 500, 0, (5 << 12) | 0x02, 65535, 0, 0)
    packet_payload = eth_hdr + ip_hdr + tcp_hdr
    pkt_hdr = struct.pack("!IIII", 1700000000, 0, len(packet_payload), len(packet_payload))

    with open(pcap_file, "wb") as f:
        f.write(global_hdr)
        f.write(pkt_hdr + packet_payload)
        f.write(pkt_hdr + packet_payload)

    reader = PcapReader()
    batches = list(reader.read_packets(pcap_file, batch_size=1))
    assert len(batches) == 2
    assert batches[0][0][0].src_ip == "10.0.0.5"
    assert batches[0][0][0].dst_ip == "10.0.0.6"


def dns_packet(payload, protocol=17, port=53):
    ethernet = b'\x00' * 12 + b'\x08\x00'
    transport = (struct.pack('!HHHH', 50000, port, 8 + len(payload), 0) if protocol == 17
                 else struct.pack('!HHIIHHHH', 50000, port, 1, 0, 5 << 12, 65535, 0, 0))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport) + len(payload),
                     1, 0, 64, protocol, 0, b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x35')
    return ethernet + ip + transport + payload


def dns_question():
    return struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0) + b'\x03www\x07example\x03org\x00' + struct.pack('!HH', 16, 1)


@pytest.mark.parametrize('protocol', [6, 17])
def test_dns_transport_framing_preserves_observed_question(protocol):
    question = dns_question()
    payload = struct.pack('!H', len(question)) + question if protocol == 6 else question
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(payload, protocol), 1700000000)
    assert flow is not None
    assert dns.query_name == 'www.example.org'
    assert dns.query_type == 16
    from ingest.metadata import from_packet
    event = from_packet(flow, dns)
    assert event.dns_name == dns.query_name
    assert event.timestamp == 1700000000000


@pytest.mark.parametrize('payload', [b'\x00', struct.pack('!H', 100) + dns_question(),
                                    struct.pack('!H', 0) + dns_question()])
def test_incomplete_dns_tcp_message_is_not_guessed(payload):
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(payload, 6), 1700000000)
    assert flow is not None and dns is None


def test_dns_name_compression_preserves_suffix_and_consumed_offset():
    payload = dns_question() + b'\x04mail\xc0\x10'
    name, end = ProtocolParser._read_dns_name(payload, len(dns_question()))
    assert name == 'mail.example.org'
    assert end == len(payload)


def test_dns_compression_work_is_bounded():
    payload = bytearray(b'\x01a\x00')
    for _ in range(130):
        target = len(payload) - 2 if len(payload) > 3 else 0
        payload.extend(struct.pack('!H', 0xC000 | target))
    with pytest.raises(ValueError, match='traversal limit'):
        ProtocolParser._read_dns_name(bytes(payload), len(payload) - 2)


@pytest.mark.parametrize('wire', [b'\xc0\x0c', b'\xc0', b'\x40x', b'\x04ab',
                                b'\x01\xff\x00', b'\x01a\xc0\x0c',
                                (b'\x3f' + b'a' * 63) * 4 + b'\x00'])
def test_malformed_dns_names_are_rejected_without_losing_ip_metadata(wire):
    payload = struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0) + wire + struct.pack('!HH', 1, 1)
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(payload), 1700000000)
    assert flow is not None and dns is None


def test_llmnr_is_not_mislabelled_as_dns_attack_input():
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(dns_question(), port=5355), 1700000000)
    assert flow is not None and dns is None


@pytest.mark.parametrize('qtype', [1, 28, 16, 10])
def test_complete_multi_label_dns_questions_preserve_record_type(qtype):
    encoded = b'j' * 63
    payload = (struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0)
               + b'\x011' + bytes([len(encoded)]) + encoded
               + b'\x04demo\x04test\x00' + struct.pack('!HH', qtype, 1))
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(payload), 1700000000)
    assert flow is not None
    assert dns.query_name == '1.' + encoded.decode() + '.demo.test'
    assert dns.query_type == qtype


def test_snaplen_clipped_question_cannot_be_scored_as_complete_dns():
    encoded = b'j' * 63
    payload = (struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0)
               + b'\x011' + bytes([len(encoded)]) + encoded
               + b'\x04demo\x04test\x00' + struct.pack('!HH', 1, 1))
    flow, dns, _ = ProtocolParser().parse_packet(dns_packet(payload)[:96], 1700000000)
    assert flow is None and dns is None


@pytest.mark.parametrize('protocol', [6, 17])
def test_long_txt_capture_metadata_reaches_streaming_detector(protocol, tmp_path, monkeypatch):
    from detection.pipeline import Pipeline
    from ingest.metadata import from_packet
    name = b'q7x9k2z4m6b8v1j3p5d0r2s4w6y8a1c3e5f7g9h0i2l4n6o8u1t3'
    question = (struct.pack('!HHHHHH', 9, 0x0100, 1, 0, 0, 0) + bytes([len(name)])
                + name + b'\x07example\x03org\x00' + struct.pack('!HH', 16, 1))
    payload = struct.pack('!H', len(question)) + question if protocol == 6 else question
    flow, dns, tls = ProtocolParser().parse_packet(dns_packet(payload, protocol), 1700000000)
    alerts = Pipeline().process(from_packet(flow, dns, tls))
    assert any(a.threat_class == 'DNS_TUNNELLING' for a in alerts)
    assert dns.query_name == name.decode() + '.example.org'
    # Exercise the same capture through upload, asynchronous replay and SQLite.
    from backend.main import app
    from fastapi.testclient import TestClient
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'dns-upload.sqlite3'))
    packet = dns_packet(payload, protocol)
    capture = (struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
               + struct.pack('!IIII', 1700000000, 0, len(packet), len(packet)) + packet)
    with TestClient(app) as client:
        assert client.post('/api/replay/pcap', content=capture).status_code == 200
        client.portal.call(lambda: app.state.replay_task)
        state = client.get('/api/telemetry').json()
        assert state['processed'] == 1 and state['replay_status'] == 'complete'
        saved = client.get('/api/alerts?threat=DNS_TUNNELLING').json()
        assert len(saved) == 1
        assert saved[0]['raw_evidence_metrics']['domain_label_length'] == len(name)

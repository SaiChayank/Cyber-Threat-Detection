"""Diagnostic-only packet inventory must distinguish DNS from port 5355."""
import struct

from datasets.audit_dns_visibility import inspect, transport, wire_dns


def _packet(port, payload):
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + len(payload),
                     1, 0, 64, 17, 0, b'\xc0\x00\x02\x01', b'\xe0\x00\x00\xfc')
    udp = struct.pack('!HHHH', 50000, port, 8 + len(payload), 0)
    return ethernet + ip + udp + payload


def test_5355_wire_question_is_visible_but_remains_separate_service():
    question = (struct.pack('!HHHHHH', 7, 0, 1, 0, 0, 0)
                + b'\x04host\x00' + struct.pack('!HH', 1, 1))
    protocol, source_port, target_port, _, destination, payload = transport(_packet(5355, question))
    assert (protocol, source_port, target_port, destination) == (17, 50000, 5355, '224.0.0.252')
    assert wire_dns(payload) == {'response': False, 'questions': [('host', 1)],
                                 'answers': [], 'bytes': len(question)}


def test_dns_answer_types_and_incomplete_tcp_are_counted_without_rdata_decoding():
    name = b'\x03www\x07example\x03org\x00'
    question = name + struct.pack('!HH', 16, 1)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 60, 4) + b'\x03abc'
    message = struct.pack('!HHHHHH', 7, 0x8180, 1, 1, 0, 0) + question + answer
    assert wire_dns(message) == {'response': True, 'questions': [('www.example.org', 16)],
                                 'answers': [16], 'bytes': len(message)}
    assert wire_dns(struct.pack('!H', len(message)) + message[:-1], tcp=True) is None


def test_truncated_udp_is_port_visible_but_not_a_complete_runtime_message():
    question = (struct.pack('!HHHHHH', 7, 0, 1, 1, 0, 0)
                + b'\x04host\x00' + struct.pack('!HH', 1, 1))
    packet = bytearray(_packet(53, question))
    struct.pack_into('!H', packet, 14 + 20 + 4, 8 + len(question) + 40)
    assert transport(bytes(packet)) is None
    visible = transport(bytes(packet), allow_truncated=True)
    assert visible[-1] is False
    assert visible[2] == 53
    assert wire_dns(visible[5]) is None
    assert wire_dns(visible[5], questions_only=True)['questions'] == [('host', 1)]


def test_inventory_records_clipped_second_label_without_inventing_qtype(tmp_path):
    payload = (struct.pack('!HHHHHH', 8, 0x0100, 1, 0, 0, 0)
               + b'\x010\x3f' + b'A' * 38)
    packet = bytearray(_packet(53, payload))
    struct.pack_into('!H', packet, 14 + 20 + 4, 8 + len(payload) + 50)
    capture = tmp_path / 'short.pcap'
    capture.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 96, 1)
                        + struct.pack('<IIII', 1, 0, len(packet), len(packet) + 50)
                        + packet)
    report = inspect(capture)
    assert report['snaplen'] == 96
    assert report['port_packets']['udp/53'] == 1
    assert report['counts']['port_53_truncated_udp'] == 1
    assert report['counts']['truncated_dns_query_header'] == 1
    assert report['truncated_dns_first_second_label_lengths'] == {'1,63': 1}
    assert report['counts']['truncated_dns_second_label_incomplete'] == 1
    assert report['counts'].get('truncated_dns_query_question_complete', 0) == 0
    assert report['dns_query_types'] == {}

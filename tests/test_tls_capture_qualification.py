"""Qualification diagnostics must not manufacture labels or runtime support."""
import csv
import io
import struct

import pytest

from datasets.qualify_tls_capture import (capture_header, complete_clienthello,
    csv_window, inspect_selected, raw_packets, tcp_metadata)
from ingest.protocol_parsers import ProtocolParser


def hello():
    body = (b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02\xc0\x2f' +
            b'\x01\x00' + b'\x00\x00')
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + struct.pack('!H', len(handshake)) + handshake


def frame(linktype=113, fragment=0):
    payload = hello()
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), 1, fragment,
                     64, 6, 0, b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02')
    tcp = struct.pack('!HHIIHHHH', 50000, 443, 123, 0, 5 << 12, 65535, 0, 0)
    link = (struct.pack('!HHH8sH', 0, 1, 6, b'\x00' * 8, 0x0800) if linktype == 113
            else b'\x00' * 12 + b'\x08\x00')
    return link + ip + tcp + payload


def header(linktype=113, nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    return struct.pack('<IHHiIII', magic, 2, 4, 0, 0, 65535, linktype)


def test_original_sll_header_fails_runtime_gate_without_conversion():
    original = header()
    _, _, _, kind, error = capture_header(original)
    assert kind == 113 and error == 'Only PCAP v2.4 Ethernet captures are supported'
    assert capture_header(header(1))[-1] is None
    assert original == header()


@pytest.mark.parametrize('nano,fraction,expected', [(False, 123456, 123456000),
                                                    (True, 123456789, 123456789)])
def test_exact_raw_timestamp_and_packet_position(nano, fraction, expected):
    endian, scale, snaplen, _, _ = capture_header(header(nano=nano))
    raw = frame()
    data = struct.pack('<IIII', 1700000000, fraction, len(raw), len(raw)) + raw
    packet = list(raw_packets(io.BytesIO(data), endian, scale, snaplen))[0]
    assert packet[:2] == (1, 1700000000000000000 + expected)
    assert packet[2] == raw


@pytest.mark.parametrize('data', [b'x', struct.pack('<IIII', 1, 0, 100, 100) + b'x'])
def test_partial_capture_cannot_be_qualified(data):
    with pytest.raises(ValueError, match='Truncated'):
        list(raw_packets(io.BytesIO(data), '<', 1000, 65535))


def test_sll_diagnostic_reads_original_ip_bytes_and_tls_payload_only():
    raw = frame()
    key, sequence, ip_bytes, payload = tcp_metadata(raw, 113)
    assert key == ('192.0.2.1', '198.51.100.2', 50000, 443, 6)
    assert sequence == 123 and ip_bytes == 40 + len(hello()) and payload == hello()
    assert complete_clienthello(payload)
    assert ProtocolParser()._try_parse_tls_client_hello(payload, 'audit', ip_bytes) is not None
    assert raw == frame()
    assert tcp_metadata(raw[:-1], 113) is None
    assert tcp_metadata(frame(fragment=0x2000), 113) is None


def test_declared_clienthello_boundary_must_fit_its_observed_record():
    raw = hello()
    assert not complete_clienthello(raw[:-1])
    bad_length = raw[:6] + (len(raw) + 100).to_bytes(3, 'big') + raw[9:]
    assert not complete_clienthello(bad_length)


def test_local_csv_offset_is_explicit_and_second_rounding_is_bounded():
    row = {'TimeStamp': '2020-03-29 11:02:15', 'Duration': '120.913760'}
    utc, _ = csv_window(row, 0)
    shifted, end = csv_window(row, -10800)
    assert shifted - utc == 10800 * 1_000_000_000
    assert shifted == 1585490535000000000
    assert end - shifted == 121913760000


@pytest.mark.parametrize('duration', ['-1', 'NaN', 'Infinity'])
def test_invalid_labelled_duration_cannot_create_a_matching_window(duration):
    with pytest.raises(ValueError, match='Invalid labelled duration'):
        csv_window({'TimeStamp': '2020-03-29 11:02:15', 'Duration': duration}, 0)


def test_visible_hello_and_doh_csv_do_not_promote_ground_truth(tmp_path):
    pcap, annotation = tmp_path / 'source.pcap', tmp_path / 'source.csv'
    raw = frame()
    pcap.write_bytes(header() + struct.pack('<IIII', 1585490535, 101599,
                                          len(raw), len(raw)) + raw)
    with annotation.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=['SourceIP', 'DestinationIP', 'SourcePort',
                               'DestinationPort', 'TimeStamp', 'Duration', 'DoH'])
        writer.writeheader()
        writer.writerow({'SourceIP': '192.0.2.1', 'DestinationIP': '198.51.100.2',
                         'SourcePort': 50000, 'DestinationPort': 443,
                         'TimeStamp': '2020-03-29 11:02:15', 'Duration': 1, 'DoH': 'True'})
    report = inspect_selected(pcap, annotation)
    assert report['clienthello_observations'][0]['packet_index'] == 1
    assert report['clienthello_observations'][0]['timestamp_ns'] == 1585490535101599000
    assert report['candidate_tuple_time_joins'][0]['clienthellos_in_window_with_inferred_offset'] == [1]
    assert report['candidate_tuple_time_joins'][0]['packets_in_window_as_if_csv_utc'] == 0
    assert not report['runtime_capture_accepted']
    assert not report['csv_utc_offset_independently_verified']
    assert not report['explicit_malicious_session_labels_verified']
    assert not report['qualified_for_current_runtime']

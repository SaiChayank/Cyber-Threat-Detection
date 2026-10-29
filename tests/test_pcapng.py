"""PCAPNG reading: Ethernet interfaces only, bounded, read-only."""
import json
import socket
import struct

import pytest
from fastapi.testclient import TestClient

from backend.application import app
from datasets import evaluate_lab
from datasets.lab_labels import FORMAT
from ingest.flow_export import read_flow_export
from ingest.pcap_reader import PcapReader, validate_capture_header
from ingest.pcapng import iter_pcapng
from replay.cli import metadata

START_S = 1_700_000_000


def block(kind, body, order='<'):
    body += b'\x00' * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack(f'{order}II', kind, total) + body + struct.pack(f'{order}I', total)


def section(order='<'):
    return block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1), order)


def interface(order='<', linktype=1, tsresol=None):
    options = b'' if tsresol is None else struct.pack(f'{order}HHB', 9, 1, tsresol) + b'\x00' * 3 + struct.pack(f'{order}HH', 0, 0)
    return block(1, struct.pack(f'{order}HHI', linktype, 0, 65535) + options, order)


def packet(order='<', interface_id=0, ticks=START_S * 1_000_000, size_offset=0, src='10.0.0.1', dst='10.0.0.2', dport=80):
    tcp = struct.pack('!HHIIHHHH', 40000, dport, 1, 1, (5 << 12) | 0x10, 1000, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    frame = b'\x00' * 12 + b'\x08\x00' + ip + tcp
    body = struct.pack(f'{order}IIIII', interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame) + size_offset) + frame
    return block(6, body, order), frame


def write(tmp_path, *parts, name='cap.pcapng'):
    path = tmp_path / name
    path.write_bytes(b''.join(parts))
    return path


@pytest.mark.parametrize('order', ['<', '>'])
def test_both_byte_orders_are_parsed_with_exact_timestamps(tmp_path, order):
    epb, frame = packet(order)
    path = write(tmp_path, section(order), interface(order), epb, packet(order, ticks=(START_S + 2) * 1_000_000)[0])
    with open(path, 'rb') as stream:
        packets = list(iter_pcapng(stream))
    assert [t for t, _ in packets] == [START_S, START_S + 2] and packets[0][1] == frame
    flows = [flow for batch in PcapReader().read_packets(path) for flow, _, _ in batch]
    assert len(flows) == 2 and flows[0].timestamp_start == START_S * 1000.0


def test_interface_timestamp_resolution_option_is_honoured(tmp_path):
    nanos = write(tmp_path, section(), interface(tsresol=9), packet(ticks=START_S * 10**9 + 500_000_000)[0], name='n.pcapng')
    with open(nanos, 'rb') as stream:
        assert next(iter_pcapng(stream))[0] == START_S + 0.5
    binary = write(tmp_path, section(), interface(tsresol=0x80 | 10), packet(ticks=1024 * START_S)[0], name='b.pcapng')
    with open(binary, 'rb') as stream:
        assert next(iter_pcapng(stream))[0] == START_S


def test_cli_and_flow_export_reader_accept_pcapng(tmp_path):
    path = write(tmp_path, section(), interface(), packet()[0], packet(ticks=(START_S + 1) * 1_000_000)[0])
    assert len(list(metadata(path))) == 2
    assert list(read_flow_export(path)) == []  # Non-export UDP ports; read without error.


@pytest.mark.parametrize('parts, message', [
    ((section(), interface(linktype=113)), 'Only Ethernet captures'),
    ((section(), packet()[0]), 'Invalid PCAPNG block'),
    ((section(), interface(), packet(interface_id=3)[0]), 'Invalid PCAPNG block'),
    ((section(), interface(), packet(size_offset=-1)[0]), 'Invalid PCAPNG block'),
])
def test_malformed_blocks_raise_fixed_diagnostics(tmp_path, parts, message):
    path = write(tmp_path, *parts)
    with pytest.raises(ValueError, match=message):
        list(PcapReader().read_packets(path))


def test_truncated_oversized_and_bad_trailer_blocks_are_rejected(tmp_path):
    good = section() + interface() + packet()[0]
    with pytest.raises(ValueError, match='Truncated PCAPNG block'):
        list(PcapReader().read_packets(write(tmp_path, good[:-6], name='t.pcapng')))
    huge = section() + struct.pack('<II', 6, 0x7FFFFFF0) + b'\x00' * 8
    with pytest.raises(ValueError, match='Invalid PCAPNG block'):
        list(PcapReader().read_packets(write(tmp_path, huge, name='h.pcapng')))
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    with pytest.raises(ValueError, match='Invalid PCAPNG block'):
        list(PcapReader().read_packets(write(tmp_path, bytes(bad), name='b.pcapng')))
    with pytest.raises(ValueError, match='PCAPNG requires'):
        validate_capture_header(section()[:20])


def test_lab_harness_scores_pcapng_capture(tmp_path):
    path = write(tmp_path, section(), interface(), packet()[0])
    labels = tmp_path / 'l.json'
    labels.write_text(json.dumps(dict(format=FORMAT, capture=path.name, episodes=[
        dict(id='web', label='BENIGN', start_ms=0, end_ms=2e12, hosts=['10.0.0.0/24'])])))
    assert evaluate_lab.evaluate([labels])['captures'][0]['events'] == 1


def test_upload_api_accepts_pcapng_and_still_rejects_garbage(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'p.db'))
    capture = section() + interface() + b''.join(packet(ticks=(START_S + i) * 1_000_000)[0] for i in range(3))
    with TestClient(app) as client:
        assert client.post('/api/replay/pcap?speed=10000', content=capture).status_code == 200
        client.portal.call(lambda: app.state.replay_task)
        state = client.get('/api/telemetry').json()
        assert state['processed'] == 3 and state['replay_status'] == 'complete'
        assert client.post('/api/replay/pcap', content=b'not a capture at all, just text').status_code == 422
        assert client.post('/api/replay/pcap', content=section()[:12]).status_code == 422

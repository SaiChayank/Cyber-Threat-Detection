"""Classic Ethernet PCAP upload/error handling through the existing API."""
import struct
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import backend.application as application


LIMIT = 16 * 1024 * 1024


def global_header(*, linktype=1, snaplen=65535):
    return struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def tcp_syn_packet():
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0,
                     b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02')
    tcp = struct.pack('!HHIIHHHH', 49152, 443, 1, 0, (5 << 12) | 2, 65535, 0, 0)
    return ethernet + ip + tcp


def entry(packet, second=1_700_000_000):
    return struct.pack('!IIII', second, 0, len(packet), len(packet)) + packet


def capture(*packets):
    return global_header() + b''.join(entry(packet, 1_700_000_000 + index * 5)
                                      for index, packet in enumerate(packets))


@pytest.fixture
def uploaded_paths(tmp_path, monkeypatch):
    paths = []
    real_create = tempfile.NamedTemporaryFile

    def tracked(*args, **kwargs):
        file = real_create(*args, dir=tmp_path, **kwargs)
        paths.append(Path(file.name))
        return file

    monkeypatch.setattr(application, 'tempfile', SimpleNamespace(NamedTemporaryFile=tracked))
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'alerts.sqlite3'))
    return paths


def assert_clean(paths):
    assert paths
    assert all(not path.exists() for path in paths)


def await_replay(client):
    client.portal.call(lambda: application.app.state.replay_task)
    return client.get('/api/telemetry').json()


def test_valid_classic_ethernet_capture_runs_and_removes_temporary_file(uploaded_paths):
    with TestClient(application.app) as client:
        response = client.post('/api/replay/pcap?speed=10000', content=capture(tcp_syn_packet()))
        assert response.status_code == 200 and response.json() == {'status': 'running'}
        state = await_replay(client)
        assert state['replay_status'] == 'complete' and state['processed'] == 1
        assert state['replay_error'] is None
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


@pytest.mark.parametrize('content,detail', [
    (b'', 'complete 24-byte header'),
    (b'pretend this is a .pcap file' + b' ' * 24, 'capture format'),
    (global_header()[:12], 'complete 24-byte header'),
    (global_header(linktype=101), 'Ethernet'),
])
def test_invalid_header_is_rejected_without_leaving_tempfile(uploaded_paths, content, detail):
    with TestClient(application.app) as client:
        response = client.post('/api/replay/pcap', content=content)
        assert response.status_code == 422
        assert detail in response.json()['detail']
        assert client.get('/api/telemetry').json()['replay_status'] == 'idle'
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


def test_invalid_packet_length_reports_failure_and_removes_tempfile(uploaded_paths):
    invalid = global_header(snaplen=64) + struct.pack('!IIII', 1_700_000_000, 0, 100, 100)
    with TestClient(application.app) as client:
        assert client.post('/api/replay/pcap', content=invalid).status_code == 200
        state = await_replay(client)
        assert state['replay_status'] == 'failed'
        assert 'packet length' in state['replay_error']
        assert state['processed'] == 0
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


def test_truncated_packet_body_reports_failure_and_removes_tempfile(uploaded_paths):
    truncated = global_header() + struct.pack('!IIII', 1_700_000_000, 0, 40, 40) + b'abc'
    with TestClient(application.app) as client:
        assert client.post('/api/replay/pcap', content=truncated).status_code == 200
        state = await_replay(client)
        assert state['replay_status'] == 'failed'
        assert 'truncated packet' in state['replay_error'].lower()
        assert state['processed'] == 0
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


def test_malformed_frame_is_dropped_without_crashing_valid_capture(uploaded_paths):
    with TestClient(application.app) as client:
        assert client.post('/api/replay/pcap', content=capture(b'\x00\x01', tcp_syn_packet())).status_code == 200
        state = await_replay(client)
        assert state['replay_status'] == 'complete' and state['processed'] == 1
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


def test_oversized_upload_is_rejected_and_removed(uploaded_paths):
    with TestClient(application.app) as client:
        response = client.post('/api/replay/pcap', content=b'X' * (LIMIT + 1))
        assert response.status_code == 413
        assert '16 MiB' in response.json()['detail']
        assert client.get('/api/telemetry').json()['replay_status'] == 'idle'
        assert_clean(uploaded_paths)
        assert client.get('/api/health').status_code == 200


def test_path_or_url_text_cannot_select_capture_source(uploaded_paths, tmp_path):
    source = tmp_path / 'existing.pcap'
    source.write_bytes(capture(tcp_syn_packet()))
    with TestClient(application.app) as client:
        for value in (str(source), 'https://example.invalid/capture.pcap'):
            response = client.post('/api/replay/pcap', content=value.encode())
            assert response.status_code == 422
        response = client.post('/api/replay/pcap', params={'path': str(source),
                                                          'url': 'https://example.invalid/capture.pcap'},
                               content=b'')
        assert response.status_code == 422
        assert client.get('/api/telemetry').json()['processed'] == 0
        assert source.read_bytes() == capture(tcp_syn_packet())
        assert_clean(uploaded_paths)


def test_stop_removes_uploaded_capture_before_remaining_packet(uploaded_paths):
    with TestClient(application.app) as client:
        response = client.post('/api/replay/pcap?speed=0.1',
                               content=capture(tcp_syn_packet(), tcp_syn_packet()))
        assert response.status_code == 200
        for _ in range(100):
            if client.get('/api/telemetry').json()['processed'] >= 1:
                break
            time.sleep(.01)
        assert client.get('/api/telemetry').json()['processed'] == 1
        assert client.post('/api/replay/stop').json() == {'status': 'stopped'}
        assert client.get('/api/telemetry').json()['processed'] == 1
        assert_clean(uploaded_paths)

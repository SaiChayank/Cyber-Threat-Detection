"""Private replay diagnostics belong in logs, not API telemetry or Monitor."""
import asyncio
import logging
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import application
from tests.test_pcap_upload import uploaded_paths, capture, tcp_syn_packet
from tests.test_replay_controls import alert_event, await_replay


PRIVATE = 'private-runbook-token C:/private/analyst/capture.pcap'


@pytest.mark.parametrize('error_type', [RuntimeError, ValueError, FileNotFoundError, sqlite3.OperationalError])
def test_runtime_failure_keeps_private_diagnostics_in_logs_and_history_recovers(
        tmp_path, monkeypatch, caplog, error_type):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'runtime.sqlite3'))
    with TestClient(application.app) as client:
        original = client.post('/api/events', json=alert_event(0)).json()

        def broken(*args, **kwargs):
            from schemas.traffic_event import TrafficEvent
            yield TrafficEvent(**alert_event(1))
            raise error_type(PRIVATE)

        with monkeypatch.context() as patch, caplog.at_level(logging.ERROR, logger='backend.application'):
            patch.setattr(application, 'scenario', broken)
            assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': 10000}).status_code == 200
            failed = await_replay(client)
        assert failed['replay_status'] == 'failed'
        assert failed['replay_error'] and PRIVATE not in failed['replay_error']
        assert PRIVATE in caplog.text
        saved = client.get('/api/alerts').json()
        assert len(saved) == 2 and saved[0] == original[0]
        assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': 10000}).status_code == 200
        recovered = await_replay(client)
        assert recovered['replay_status'] == 'complete' and recovered['replay_error'] is None
        assert client.get('/api/alerts').json() == saved


@pytest.mark.parametrize('mode', ['complete', 'processing_failure', 'immediate_stop'])
def test_cleanup_errors_are_safe_and_logged(tmp_path, monkeypatch, caplog, mode):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'cleanup.sqlite3'))

    class BrokenSource:
        def __iter__(self):
            if mode == 'processing_failure':
                raise RuntimeError(PRIVATE)
            return iter(())

        def close(self):
            raise OSError(PRIVATE)

    async def exercise():
        cleaned = []
        application.start_replay(BrokenSource(), 10000, lambda: cleaned.append(True))
        if mode == 'immediate_stop':
            await application.stop()
        else:
            await application.app.state.replay_task
        return cleaned

    with TestClient(application.app) as client, caplog.at_level(logging.ERROR, logger='backend.application'):
        saved = client.post('/api/events', json=alert_event(0)).json()
        assert client.portal.call(exercise) == [True]
        state = client.get('/api/telemetry').json()
        assert state['replay_status'] == 'failed'
        assert 'cleanup' in state['replay_error'].lower() and PRIVATE not in state['replay_error']
        assert PRIVATE in caplog.text
        assert client.get('/api/alerts').json() == saved
        assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': 10000}).status_code == 200
        assert await_replay(client)['replay_error'] is None


@pytest.mark.parametrize('error_type', [PermissionError, ValueError])
def test_header_read_failure_is_safe_and_staged_file_removed(uploaded_paths, monkeypatch, caplog, error_type):
    real_open = Path.open

    def broken_open(path, *args, **kwargs):
        if path in uploaded_paths:
            raise error_type(PRIVATE)
        return real_open(path, *args, **kwargs)

    with TestClient(application.app, raise_server_exceptions=False) as client:
        saved = client.post('/api/events', json=alert_event(0)).json()
        with monkeypatch.context() as patch, caplog.at_level(logging.ERROR, logger='backend.application'):
            patch.setattr(Path, 'open', broken_open)
            response = client.post('/api/replay/pcap', content=capture(tcp_syn_packet()))
        assert response.status_code == 503
        assert PRIVATE not in response.text and PRIVATE in caplog.text
        assert uploaded_paths and all(not path.exists() for path in uploaded_paths)
        assert client.get('/api/alerts').json() == saved
        assert client.post('/api/replay/pcap?speed=10000', content=capture(tcp_syn_packet())).status_code == 200
        assert await_replay(client)['replay_status'] == 'complete'

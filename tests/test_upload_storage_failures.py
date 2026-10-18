"""Staging failures must preserve history, clean files and allow the next upload."""
import asyncio
import errno
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
from starlette.requests import ClientDisconnect

import backend.application as application
from tests.test_pcap_upload import uploaded_paths, capture, tcp_syn_packet, await_replay
from tests.test_replay_controls import alert_event


@pytest.mark.parametrize('stage', ['allocate', 'write', 'close'])
@pytest.mark.parametrize('error_number', [errno.ENOSPC, errno.EACCES])
def test_temporary_storage_failure_is_retryable_and_cleans_staged_file(
        uploaded_paths, monkeypatch, stage, error_number):
    with TestClient(application.app, raise_server_exceptions=False) as client:
        original = client.post('/api/events', json=alert_event(0)).json()
        assert len(original) == 1
        state_before = client.get('/api/telemetry').json()
        real_create = application.tempfile.NamedTemporaryFile
        private_detail = '/private/local/capture-staging'

        def fail():
            raise OSError(error_number, 'controlled storage failure', private_detail)

        class FaultyFile:
            def __init__(self, file):
                self.file = file
                self.name = file.name

            def __enter__(self):
                self.file.__enter__()
                return self

            def __exit__(self, *args):
                result = self.file.__exit__(*args)
                if stage == 'close':
                    fail()
                return result

            def close(self):
                return self.file.close()

            def write(self, chunk):
                if stage == 'write':
                    fail()
                return self.file.write(chunk)

        def broken_create(*args, **kwargs):
            if stage == 'allocate':
                fail()
            return FaultyFile(real_create(*args, **kwargs))

        with monkeypatch.context() as patch:
            patch.setattr(application.tempfile, 'NamedTemporaryFile', broken_create)
            response = client.post('/api/replay/pcap', content=capture(tcp_syn_packet()))
        assert response.status_code == 503
        assert 'storage' in response.json()['detail'].lower()
        assert private_detail not in response.text
        assert all(not Path(path).exists() for path in uploaded_paths)
        assert client.get('/api/health').status_code == 200
        assert client.get('/api/alerts').json() == original
        state_after = client.get('/api/telemetry').json()
        assert state_after['processed'] == state_before['processed'] == 1
        assert state_after['replay_status'] == state_before['replay_status'] == 'idle'
        assert state_after['replay_error'] is None

        assert client.post('/api/replay/pcap?speed=10000',
                           content=capture(tcp_syn_packet())).status_code == 200
        recovered = await_replay(client)
        assert recovered['replay_status'] == 'complete' and recovered['processed'] == 1
        assert client.get('/api/alerts').json() == original
        assert all(not Path(path).exists() for path in uploaded_paths)


@pytest.mark.parametrize('interruption', [asyncio.CancelledError, ClientDisconnect])
def test_interrupted_staging_cleans_up_without_becoming_storage_error(uploaded_paths, interruption):
    async def interrupted_stream():
        yield capture(tcp_syn_packet())[:24]
        raise interruption()

    with TestClient(application.app) as client:
        original = client.post('/api/events', json=alert_event(0)).json()
        with pytest.raises(interruption):
            asyncio.run(application.pcap(SimpleNamespace(stream=interrupted_stream), speed=20))
        assert uploaded_paths and all(not path.exists() for path in uploaded_paths)
        assert client.get('/api/alerts').json() == original
        state = client.get('/api/telemetry').json()
        assert state['replay_status'] == 'idle' and state['processed'] == 1

"""Storage read failures are safe API errors or resumable stream closures."""
import asyncio
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

import backend.application as application
from tests.test_sqlite_restart import stored_alert


PRIVATE_DETAIL = 'controlled read fault /private/analyst/history.sqlite3'
READS = [('/api/alerts', 'list'), ('/api/telemetry', 'summary'), ('/api/stream', 'list')]


def fail_with(error):
    def read(*args, **kwargs):
        raise error
    return read


@pytest.mark.parametrize('route,operation', READS)
@pytest.mark.parametrize('error_type', [sqlite3.OperationalError, sqlite3.DatabaseError,
                                       sqlite3.ProgrammingError])
def test_read_failure_is_safe_503_and_existing_history_recovers(
        tmp_path, monkeypatch, route, operation, error_type):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'history.sqlite3'))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        store = application.app.state.store
        original = [store.append(stored_alert('first')),
                    store.append(stored_alert('second', 'DGA_DOMAINS'))]
        with monkeypatch.context() as fault:
            fault.setattr(store, operation, fail_with(error_type(PRIVATE_DETAIL)))
            response = client.get(route)
        assert response.status_code == 503
        assert response.headers['content-type'] == 'application/json'
        assert response.json()['detail'] == 'Alert history temporarily unavailable; retry after storage recovery'
        assert PRIVATE_DETAIL not in response.text
        assert client.get('/api/alerts?limit=1').json() == original[:1]
        assert client.get('/api/alerts?after=1&limit=1').json() == original[1:]
        assert client.get('/api/alerts?threat=DDOS').json() == original[:1]
        assert client.get('/api/alerts?newest=true').json() == original[::-1]
        assert client.get('/api/telemetry').json()['alerts_by_class'] == {'DDOS': 1, 'DGA_DOMAINS': 1}


@pytest.mark.parametrize('route,operation', READS)
def test_unrelated_programming_error_is_not_translated(tmp_path, monkeypatch, route, operation):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'programming.sqlite3'))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        monkeypatch.setattr(application.app.state.store, operation,
                            fail_with(RuntimeError('unrelated programming defect')))
        assert client.get(route).status_code == 500


@pytest.mark.parametrize('route,operation', READS)
def test_actual_closed_sqlite_connection_returns_503(tmp_path, monkeypatch, route, operation):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'closed.sqlite3'))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        application.app.state.store.close()
        response = client.get(route)
        assert response.status_code == 503
        assert 'closed database' not in response.text


class ConnectedRequest:
    def __init__(self, last_id='0'):
        self.headers = {'last-event-id': last_id}

    async def is_disconnected(self):
        return False


def parse_frame(frame):
    lines = frame.splitlines()
    record = json.loads(next(line[6:] for line in lines if line.startswith('data: ')))
    assert int(next(line[4:] for line in lines if line.startswith('id: '))) == record['sequence']
    return record


@pytest.mark.parametrize('initial_alert', [False, True])
def test_late_read_failure_closes_stream_and_durable_resume_has_no_gap_or_duplicate(
        tmp_path, monkeypatch, initial_alert):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'resume.sqlite3'))
    with TestClient(application.app):
        store = application.app.state.store
        first = store.append(stored_alert('before-disconnect')) if initial_alert else None

        async def exercise():
            response = await application.stream(ConnectedRequest(), after=0)
            iterator = response.body_iterator
            frame = await asyncio.wait_for(anext(iterator), timeout=2)
            received = [parse_frame(frame)] if initial_alert else []
            assert received == ([first] if initial_alert else [])
            if not initial_alert:
                assert frame == ': heartbeat\n\n'
            # These become durable during the disconnect, without being delivered.
            missed = [store.append(stored_alert('during-disconnect-1')),
                      store.append(stored_alert('during-disconnect-2'))]
            with monkeypatch.context() as fault:
                fault.setattr(store, 'list', fail_with(sqlite3.OperationalError(PRIVATE_DETAIL)))
                with pytest.raises(StopAsyncIteration):
                    await asyncio.wait_for(anext(iterator), timeout=2)
            cursor = received[-1]['sequence'] if received else 0
            # Header takes precedence over an older query cursor, as in EventSource.
            resumed = await application.stream(ConnectedRequest(str(cursor)), after=0)
            try:
                recovered = [parse_frame(await asyncio.wait_for(anext(resumed.body_iterator), timeout=2))
                             for _ in missed]
                assert recovered == missed
                combined = received + recovered
                assert combined == store.list()
                assert len({row['alert_id'] for row in combined}) == len(combined)
            finally:
                await resumed.body_iterator.aclose()
        asyncio.run(exercise())

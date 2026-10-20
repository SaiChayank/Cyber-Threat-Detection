"""Malformed durable bodies fail closed without dropping history or a sequence."""
import asyncio
import sqlite3

from fastapi.testclient import TestClient
import pytest

from backend import application
from persistence.store import AlertStore
from tests.test_sqlite_restart import stored_alert
from tests.test_sqlite_read_recovery import ConnectedRequest, parse_frame


BAD_BODIES = ['{private-json-sentinel', '[]', 'null', '"private-json-sentinel"',
              'NaN', b'\xff', None]


def corrupt(store, sequence, body):
    original = store.connection.execute('SELECT body FROM alerts WHERE sequence=?', (sequence,)).fetchone()[0]
    store.connection.execute('UPDATE alerts SET body=? WHERE sequence=?', (body, sequence))
    store.connection.commit()
    return original


@pytest.mark.parametrize('body', BAD_BODIES)
def test_bad_stored_body_is_storage_error_without_partial_results_or_modification(tmp_path, body):
    store = AlertStore(tmp_path/'bad-body.sqlite3')
    try:
        first = store.append(stored_alert('valid-first'))
        second = store.append(stored_alert('corrupt-second'))
        original = corrupt(store, second['sequence'], body)
        rows = store.connection.execute('SELECT sequence,alert_id,threat,body FROM alerts ORDER BY sequence').fetchall()
        with pytest.raises(sqlite3.DatabaseError, match='Stored alert data is unreadable'):
            store.list()
        assert store.connection.execute('SELECT sequence,alert_id,threat,body FROM alerts ORDER BY sequence').fetchall() == rows
        assert store.list(limit=1) == [first]
        corrupt(store, second['sequence'], original)
        assert store.list() == [first, second]
    finally:
        store.close()


@pytest.mark.parametrize('route', ['/api/alerts','/api/stream'])
@pytest.mark.parametrize('body', BAD_BODIES)
def test_bad_stored_body_uses_existing_safe_read_503_then_recovers(tmp_path, monkeypatch, route, body):
    monkeypatch.setenv('ALERT_DB', str(tmp_path/'api-body.sqlite3'))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        store = application.app.state.store
        saved = [store.append(stored_alert('first')), store.append(stored_alert('second'))]
        original = corrupt(store, 2, body)
        response = client.get(route)
        assert response.status_code == 503
        assert response.json()['detail'] == 'Alert history temporarily unavailable; retry after storage recovery'
        assert 'private-json-sentinel' not in response.text
        assert client.get('/api/health').status_code == 200
        corrupt(store, 2, original)
        assert client.get('/api/alerts').json() == saved
        assert client.get('/api/alerts?after=1').json() == saved[1:]


@pytest.mark.parametrize('initial_alert', [False, True])
def test_late_body_corruption_ends_stream_and_recovers_next_durable_sequence(tmp_path, monkeypatch, initial_alert):
    monkeypatch.setenv('ALERT_DB', str(tmp_path/'late-body.sqlite3'))
    with TestClient(application.app):
        store = application.app.state.store
        first = store.append(stored_alert('before')) if initial_alert else None

        async def exercise():
            response = await application.stream(ConnectedRequest(),after=0)
            frame = await asyncio.wait_for(anext(response.body_iterator),timeout=2)
            delivered = [parse_frame(frame)] if initial_alert else []
            assert delivered == ([first] if initial_alert else [])
            missed = [store.append(stored_alert('missed-one')),store.append(stored_alert('missed-two'))]
            original = corrupt(store, missed[0]['sequence'], '{private-json-sentinel')
            with pytest.raises(StopAsyncIteration):
                await asyncio.wait_for(anext(response.body_iterator),timeout=2)
            corrupt(store, missed[0]['sequence'], original)
            cursor = first['sequence'] if first else 0
            resumed = await application.stream(ConnectedRequest(str(cursor)),after=0)
            try:
                recovered = [parse_frame(await asyncio.wait_for(anext(resumed.body_iterator),timeout=2)) for _ in missed]
                assert recovered == missed and delivered+recovered == store.list()
                assert len({row['alert_id'] for row in delivered+recovered}) == len(delivered+recovered)
            finally:
                await resumed.body_iterator.aclose()
        asyncio.run(exercise())

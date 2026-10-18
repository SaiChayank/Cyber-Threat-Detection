"""Malformed resume cursors must not reach SQLite or start a broken stream."""
import asyncio

from fastapi.testclient import TestClient
import httpx
import pytest

import backend.application as application
from tests.test_sse_resume import local_api


MAX_SEQUENCE = (1 << 63) - 1


@pytest.mark.parametrize('endpoint,headers', [
    (f'/api/alerts?after={MAX_SEQUENCE + 1}', {}),
    (f'/api/alerts?after={10 ** 100}', {}),
    (f'/api/stream?after={MAX_SEQUENCE + 1}', {}),
    (f'/api/stream?after={10 ** 100}', {}),
    ('/api/stream', {'Last-Event-ID': str(MAX_SEQUENCE + 1)}),
    ('/api/stream?after=1', {'Last-Event-ID': str(10 ** 100)}),
])
def test_oversized_cursor_is_rejected_before_database_access(tmp_path, monkeypatch, endpoint, headers):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'rejected.sqlite3'))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        accessed = []
        def unexpected_read(*args, **kwargs):
            accessed.append((args, kwargs))
            raise RuntimeError('Invalid cursor reached persistence')
        monkeypatch.setattr(application.app.state.store, 'list', unexpected_read)
        response = client.get(endpoint, headers=headers)
        assert response.status_code == 422
        assert response.json()['detail']
        assert accessed == []
        assert client.get('/api/health').status_code == 200


def test_alert_cursor_signed_upper_boundary_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'boundary.sqlite3'))
    with TestClient(application.app) as client:
        response = client.get('/api/alerts', params={'after': MAX_SEQUENCE})
        assert response.status_code == 200 and response.json() == []


async def first_stream_line(client, after, last_id):
    headers = {'Last-Event-ID': last_id} if last_id is not None else {}
    async with client.stream('GET', '/api/stream', params={'after': after}, headers=headers) as response:
        response.raise_for_status()
        async with asyncio.timeout(5):
            async for line in response.aiter_lines():
                if line:
                    return line
    raise AssertionError('No SSE heartbeat')


def test_valid_boundaries_and_existing_malformed_header_fallback_stream(tmp_path):
    async def exercise(base):
        async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=5) as client:
            for after, header in [(MAX_SEQUENCE, None), (0, str(MAX_SEQUENCE)),
                                  (0, 'not-a-sequence'), (0, '-1')]:
                assert await first_stream_line(client, after, header) == ': heartbeat'
    with local_api(tmp_path / 'stream-boundaries.sqlite3') as base:
        asyncio.run(exercise(base))

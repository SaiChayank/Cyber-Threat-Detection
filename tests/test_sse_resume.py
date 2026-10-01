"""Real loopback SSE disconnect/resume integration against isolated SQLite."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def local_api(database):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    log_path = database.with_suffix('.api.log')
    with log_path.open('a', encoding='utf-8') as log:
        process = subprocess.Popen(
            [sys.executable, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1',
             '--port', str(port), '--log-level', 'warning', '--no-access-log'],
            cwd=ROOT, env=os.environ | {'ALERT_DB': str(database)}, stdout=log, stderr=log,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        try:
            with httpx.Client(trust_env=False, timeout=.5) as client:
                for _ in range(50):
                    if process.poll() is not None:
                        raise AssertionError(f'API exited:\n{log_path.read_text()[-2000:]}')
                    try:
                        if client.get(base + '/api/health').status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.1)
                else:
                    raise AssertionError(f'API did not start:\n{log_path.read_text()[-2000:]}')
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def event(index):
    return dict(timestamp=1_700_000_000_000 + index * 31_000,
                src_ip=f'192.0.2.{index % 254 + 1}', dst_ip='198.51.100.1',
                dst_port=443, protocol=17, packets=12_000, bytes=720_000,
                flow_id=f'sse-resume-{index}')


async def submit(client, index):
    response = await client.post('/api/events', json=event(index))
    response.raise_for_status()
    rows = response.json()
    assert len(rows) == 1 and rows[0]['threat_class'] == 'DDOS'
    assert rows[0]['flow_id'] == f'sse-resume-{index}'
    return rows[0]


async def receive(client, count, *, after=0, last_id=None, ready=None):
    headers = {'Last-Event-ID': str(last_id)} if last_id is not None else {}
    rows = []
    sse_id = None
    async with client.stream('GET', f'/api/stream?after={after}', headers=headers,
                             timeout=None) as response:
        response.raise_for_status()
        assert response.headers['content-type'].startswith('text/event-stream')
        if ready:
            ready.set()
        async for line in response.aiter_lines():
            if line.startswith('id: '):
                sse_id = line[4:]
            elif line.startswith('data: '):
                row = json.loads(line[6:])
                assert sse_id == str(row['sequence'])
                rows.append(row)
                sse_id = None
                if len(rows) == count:
                    return rows  # Exiting the stream context forces disconnect.
    raise AssertionError('SSE ended before the expected alerts arrived')


async def disconnect_and_resume(base):
    async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=10) as client:
        ready = asyncio.Event()
        initial = asyncio.create_task(receive(client, 3, ready=ready))
        await asyncio.wait_for(ready.wait(), 5)
        accepted = [await submit(client, index) for index in range(3)]
        first = await asyncio.wait_for(initial, 5)
        assert first == accepted

        # No SSE subscriber exists while these 105 alerts are committed. This
        # exceeds the endpoint's 100-row fetch page and exercises pagination.
        accepted.extend([await submit(client, index) for index in range(3, 108)])
        stored_response = await client.get('/api/alerts?limit=1000')
        stored_response.raise_for_status()
        assert stored_response.json() == accepted

        resumed = await asyncio.wait_for(
            receive(client, 105, after=0, last_id=first[-1]['sequence']), 10)
        assert resumed == accepted[3:]
        assert [row['sequence'] for row in first + resumed] == [row['sequence'] for row in accepted]
        assert len({row['alert_id'] for row in first + resumed}) == 108
        return accepted


async def resume_after_restart(base, accepted):
    async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=10) as client:
        stored = await client.get('/api/alerts?limit=1000')
        stored.raise_for_status()
        assert stored.json() == accepted  # SQLite, not a process-local SSE queue.

        ready = asyncio.Event()
        # A stale query cursor cannot override the newer Last-Event-ID.
        resumed = asyncio.create_task(receive(
            client, 1, after=0, last_id=accepted[-1]['sequence'], ready=ready))
        await asyncio.wait_for(ready.wait(), 5)
        new = await submit(client, 108)
        assert await asyncio.wait_for(resumed, 5) == [new]

        # An explicit query cursor also resumes correctly without the header.
        ready = asyncio.Event()
        next_stream = asyncio.create_task(receive(client, 1, after=new['sequence'], ready=ready))
        await asyncio.wait_for(ready.wait(), 5)
        more = await submit(client, 109)
        assert await asyncio.wait_for(next_stream, 5) == [more]
        final = (await client.get('/api/alerts?limit=1000')).json()
        assert final == accepted + [new, more]
        assert len({row['sequence'] for row in final}) == len(final) == 110


def test_sse_disconnect_resume_uses_persisted_cursor_without_gaps(tmp_path):
    database = tmp_path / 'sse-resume.sqlite3'
    with local_api(database) as base:
        accepted = asyncio.run(disconnect_and_resume(base))
    with local_api(database) as base:
        asyncio.run(resume_after_restart(base, accepted))

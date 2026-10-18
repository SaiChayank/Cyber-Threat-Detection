"""Observe the isolated UI-triggered demo; never writes the original analyst DB."""
import asyncio
import json
from pathlib import Path
import sqlite3
import sys
import time

import httpx
from rehearse import CHECKOUT, save

BASE = 'http://127.0.0.1:13418'


def persisted():
    path = CHECKOUT / 'data/alerts.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        return [json.loads(body) | {'sequence': sequence}
                for sequence, body in db.execute('SELECT sequence, body FROM alerts ORDER BY sequence')]


async def observe():
    async with httpx.AsyncClient(base_url=BASE, trust_env=False, timeout=10) as client:
        initial = (await client.get('/api/alerts')).json()
        assert initial == persisted() == [], 'Demo must begin with empty isolated history'
        received, positions = [], []

        async def stream():
            async with client.stream('GET', '/api/stream', timeout=None) as response:
                response.raise_for_status()
                save('observer-ready.json', dict(connected=True, proxy=BASE, initial_records=0))
                event_id = None
                async for line in response.aiter_lines():
                    if line.startswith('id: '):
                        event_id = line[4:]
                    elif line.startswith('data: '):
                        row = json.loads(line[6:])
                        assert event_id == str(row['sequence'])
                        received.append(row)

        observer = asyncio.create_task(stream())
        try:
            until = time.monotonic() + 240
            while time.monotonic() < until:
                telemetry = (await client.get('/api/telemetry')).json()
                rows = (await client.get('/api/alerts')).json()
                if rows:
                    positions.append(dict(processed=telemetry['processed'], status=telemetry['replay_status'], alerts=len(rows)))
                if telemetry['replay_status'] == 'complete':
                    break
                if telemetry['replay_status'] == 'failed':
                    raise RuntimeError(telemetry)
                await asyncio.sleep(.25)
            else:
                raise RuntimeError('Timed out waiting for UI-triggered demo completion')
            for _ in range(20):
                if len(received) == len(rows):
                    break
                await asyncio.sleep(.1)
            assert telemetry['processed'] == 256
            assert len(rows) == len(received) == len(persisted()) == 15
            assert rows == received == persisted()
            assert len({r['alert_id'] for r in rows}) == 15
            assert len({r['threat_class'] for r in rows}) == 7
            assert any(p['status'] == 'running' and p['processed'] < 256 for p in positions)
            save('demo-integration.json', dict(telemetry=telemetry, alerts=rows,
                 sse_matches_api_and_sqlite=True, unique_alert_ids=15,
                 incremental_positions=positions, scope='UI-triggered replay, Next proxy API/SSE, read-only SQLite comparison; no browser latency measurement'))
            print('DEMO_INTEGRATION_PASS', flush=True)
        finally:
            observer.cancel()
            try:
                await observer
            except asyncio.CancelledError:
                pass


async def restart():
    expected = json.loads((Path(__file__).parent / 'demo-integration.json').read_text())['alerts']
    async with httpx.AsyncClient(base_url=BASE, trust_env=False, timeout=10) as client:
        rows = (await client.get('/api/alerts')).json()
        state = (await client.get('/api/telemetry')).json()
        assert rows == persisted() == expected
        assert state['replay_status'] == 'idle' and state['processed'] == 0
        save('restart-persistence.json', dict(records=15, records_identical=True,
                                             telemetry=state, persisted_matches=True))
        print('RESTART_PERSISTENCE_PASS', flush=True)


if __name__ == '__main__':
    asyncio.run({'observe': observe, 'restart': restart}[sys.argv[1]]())

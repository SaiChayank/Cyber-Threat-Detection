"""Reuse the established proxy/API/SQLite observer with this isolated checkout."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys

from rehearse import CHECKOUT, HERE, save

spec = importlib.util.spec_from_file_location('prior_observer', HERE.parent / 'clean-checkout-20261018/live_verify.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.BASE = 'http://127.0.0.1:13420'


async def restart():
    expected = json.loads((HERE / 'demo-integration.json').read_text())['alerts']
    import httpx
    async with httpx.AsyncClient(base_url=prior.BASE, trust_env=False, timeout=10) as client:
        response = await client.get('/api/alerts')
        response.raise_for_status()
        rows = response.json()
        state = (await client.get('/api/telemetry')).json()
        assert rows == prior.persisted() == expected
        assert state['replay_status'] == 'idle' and state['processed'] == 0
        after = expected[6]['sequence']
        resumed = []
        async with client.stream('GET', '/api/stream', headers={'Last-Event-ID': str(after)}, timeout=10) as stream:
            stream.raise_for_status()
            sequence = None
            async for line in stream.aiter_lines():
                if line.startswith('id: '):
                    sequence = line[4:]
                elif line.startswith('data: '):
                    row = json.loads(line[6:])
                    assert sequence == str(row['sequence'])
                    resumed.append(row)
                    if len(resumed) == len(expected[7:]):
                        break
        assert resumed == expected[7:]
        assert len({row['alert_id'] for row in resumed}) == len(resumed)
        save('restart-persistence.json', dict(records=len(rows), records_identical=True,
            fresh_idle_telemetry=state, resumed_after_sequence=after,
            exact_resumed_records=len(resumed), no_duplicate_records=True,
            scope='Production restart, proxy API/SSE and read-only isolated SQLite'))
        print('RESTART_AND_RESUME_PASS', flush=True)


if __name__ == '__main__':
    asyncio.run({'observe': prior.observe, 'restart': restart}[sys.argv[1]]())

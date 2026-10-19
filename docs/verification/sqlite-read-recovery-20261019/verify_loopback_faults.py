"""Real HTTP/SSE storage-fault check; test injection exists only in this process."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def serve(port, marker):
    from persistence.store import AlertStore
    import uvicorn
    for operation in ('list', 'summary'):
        original = getattr(AlertStore, operation)
        def controlled_read(self, *args, _original=original, **kwargs):
            if marker.exists():
                raise sqlite3.OperationalError('controlled temporary storage read failure')
            return _original(self, *args, **kwargs)
        setattr(AlertStore, operation, controlled_read)
    uvicorn.run('backend.main:app', host='127.0.0.1', port=port, log_level='warning', access_log=False)


async def exercise(base, marker):
    import httpx
    from tests.test_sse_resume import receive, submit
    async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=5) as client:
        accepted = [await submit(client, 0)]
        async with client.stream('GET', '/api/stream') as response:
            assert response.status_code == 200
            async with asyncio.timeout(5):
                lines = response.aiter_lines()
                async for line in lines:
                    if line.startswith('id: '):
                        last_id = int(line[4:])
                    if line.startswith('data: '):
                        assert json.loads(line[6:]) == accepted[0]
                        assert last_id == accepted[0]['sequence']
                        break
                else:
                    raise AssertionError('No initial SSE alert')
                marker.write_bytes(b'read fault enabled in owned test server only')
                # A clean EOF proves the real response closes after a late fault.
                assert [line async for line in lines if line] == []
        accepted.extend([await submit(client, index) for index in (1, 2)])
        failures = {}
        for route in ('/api/alerts', '/api/telemetry', '/api/stream'):
            response = await client.get(route)
            assert response.status_code == 503
            assert response.json()['detail'] == 'Alert history temporarily unavailable; retry after storage recovery'
            failures[route] = response.status_code
        marker.unlink()
        recovered = await asyncio.wait_for(receive(client, 2, last_id=last_id), 5)
        assert recovered == accepted[1:]
        stored = (await client.get('/api/alerts')).json()
        assert stored == accepted
        assert len({row['alert_id'] for row in accepted}) == 3
        assert (await client.get('/api/telemetry')).json()['alerts_by_class'] == {'DDOS': 3}
        return accepted, failures


def main():
    import httpx
    with tempfile.TemporaryDirectory(prefix='univect-read-recovery-') as directory:
        database = Path(directory) / 'isolated.sqlite3'
        marker = Path(directory) / 'read-fault'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        with (HERE / 'loopback-fault-server.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen([sys.executable, '-B', __file__, '--serve', str(port), str(marker)],
                cwd=ROOT, env=os.environ | {'ALERT_DB': str(database)}, stdout=log, stderr=log,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                with httpx.Client(trust_env=False, timeout=.5) as client:
                    for _ in range(60):
                        assert process.poll() is None, 'Owned test API exited'
                        try:
                            if client.get(base + '/api/health').status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(.1)
                    else:
                        raise AssertionError('Owned test API did not start')
                accepted, failures = asyncio.run(exercise(base, marker))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        from persistence.store import AlertStore
        reopened = AlertStore(database)
        try:
            assert reopened.list() == accepted
        finally:
            reopened.close()
        result = dict(passed=True, scope='Real loopback HTTP/SSE with isolated controlled SQLite read faults',
            initial_alert_received=True, late_fault_clean_eof=True, initial_fault_statuses=failures,
            records_durable_during_disconnect=2, exact_resumed_records=2, persisted_total=3,
            duplicates=0, history_unchanged_after_process_exit=True,
            persisted_records_sha256=hashlib.sha256(json.dumps(accepted, sort_keys=True).encode()).hexdigest(),
            production_fault_switch_added=False, physical_corruption_repair_tested=False)
        (HERE / 'loopback-fault-result.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
        print(json.dumps(result))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--serve':
        serve(int(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()

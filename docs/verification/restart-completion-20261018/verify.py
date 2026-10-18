"""Complete the frozen rehearsal using its actual retained history; no new ingest."""
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import time

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PRIOR = ROOT / 'docs/verification/clean-checkout-20261018'
CHECKOUT = Path(os.environ['LOCALAPPDATA']) / 'Temp/univect-clean-20261018-4e92b3b'
BASE = 'http://127.0.0.1:13418'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def history():
    uri = (CHECKOUT / 'data/alerts.sqlite3').as_uri() + '?mode=ro'
    with sqlite3.connect(uri, uri=True) as database:
        return [json.loads(body) | {'sequence': seq}
                for seq, body in database.execute('SELECT sequence, body FROM alerts ORDER BY sequence')]


def check_prerequisites():
    assert CHECKOUT.is_dir(), 'Retained clean checkout missing'
    revision = subprocess.check_output(['git', 'rev-parse', '--short=7', 'HEAD'], cwd=CHECKOUT).decode().strip()
    assert revision == '4e92b3b', 'Unexpected application commit'
    expected = json.loads((PRIOR / 'pre-restart-history.json').read_text())['alerts']
    assert len(expected) == 30 and history() == expected, 'Retained history differs'
    runtime = json.loads((PRIOR / 'core-benchmark.json').read_text())['runtime_source_sha256']
    runtime |= {name: sha(ROOT / name) for name in ('backend/application.py', 'backend/main.py',
                                                   'scripts/run-local.mjs', 'scripts/setup-python.mjs')}
    for name, value in runtime.items():
        assert sha(CHECKOUT / name) == value == sha(ROOT / name), name
    for sidecar in (CHECKOUT / 'ml').glob('*.sha256'):
        assert sha(sidecar.with_suffix('.json')) == sidecar.read_text().split()[0]
    for port in (18418, 13418):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    prior_pins = json.loads((PRIOR / 'integrity-after.json').read_text())
    before = {name: sha(ROOT / name) for name in prior_pins}
    assert before == prior_pins, 'Protected originals differ from prior checkpoint'
    save('integrity-before.json', before)
    save('selection.json', dict(application_commit=revision,
         retained_snapshot_sha256=sha(PRIOR / 'pre-restart-history.json'),
         expected_records=30, runtime_sha256=runtime, no_ingest_requests=True,
         protocol_sha256=sha(HERE / 'PROTOCOL.md')))
    return expected, before


def launch(label):
    environment = dict(os.environ)
    for name in ('VIRTUAL_ENV', 'PYTHONHOME', 'PYTHONPATH', 'PYTHON_EXECUTABLE',
                 'API_HOST', 'API_PORT', 'API_PROXY_URL', 'WEB_PORT', 'ALERT_DB'):
        environment.pop(name, None)
    environment['PYTHONIOENCODING'] = 'utf-8'
    with (HERE / f'{label}.log').open('wb') as output:
        process = subprocess.Popen([shutil.which('npm.cmd'), 'start'], cwd=CHECKOUT,
                                   env=environment, stdout=output, stderr=subprocess.STDOUT)
    save(f'{label}-process.json', dict(pid=process.pid, checkout=str(CHECKOUT)))
    return process


def stop(process, label):
    if process.poll() is None:
        result = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (HERE / f'{label}-cleanup.log').write_bytes(result.stdout)
        assert result.returncode == 0, 'Owned cleanup failed'
        process.wait(timeout=20)


async def verify(client, expected, *, resume):
    rows = (await client.get('/api/alerts?limit=1000')).raise_for_status().json()
    assert rows == history() == expected
    telemetry = (await client.get('/api/telemetry')).raise_for_status().json()
    assert telemetry['processed'] == 0 and telemetry['replay_status'] == 'idle'
    assert telemetry['replay_error'] is None
    assert telemetry['alerts_by_class'] == dict(Counter(r['threat_class'] for r in expected))
    pages, after = [], 0
    while True:
        page = (await client.get('/api/alerts', params={'limit': 7, 'after': after})).raise_for_status().json()
        if not page:
            break
        pages.extend(page)
        after = page[-1]['sequence']
    assert pages == expected
    assert (await client.get('/api/alerts?newest=true&limit=1000')).json() == expected[::-1]
    for threat in telemetry['alerts_by_class']:
        selected = (await client.get('/api/alerts', params={'threat': threat, 'limit': 1000})).raise_for_status().json()
        assert selected == [r for r in expected if r['threat_class'] == threat]
    result = dict(records=len(rows), records_ids_order_evidence_identical=True,
                  idle_runtime_reset=True, pagination_matches=True,
                  seven_threat_filters_match=True, telemetry=telemetry)
    if resume:
        cursor = expected[14]['sequence']
        received, ids = [], []
        async with client.stream('GET', '/api/stream', headers={'Last-Event-ID': str(cursor)}) as response:
            response.raise_for_status()
            event_id = None
            async with asyncio.timeout(15):
                async for line in response.aiter_lines():
                    if line.startswith('id: '):
                        event_id = line[4:]
                    elif line.startswith('data: '):
                        row = json.loads(line[6:])
                        assert event_id == str(row['sequence'])
                        received.append(row)
                        ids.append(event_id)
                    elif line == ': heartbeat' and received:
                        # Observe the complete backlog, not only the expected first N.
                        break
        assert received == expected[15:]
        assert len(ids) == len(set(ids)) == 15
        result |= dict(resume_after_sequence=cursor, resumed_records=15,
                       resume_records_exact=True, duplicate_resume_records=0)
    return result


async def lifetime(label, expected, resume=False):
    process = launch(label)
    try:
        async with httpx.AsyncClient(base_url=BASE, trust_env=False, timeout=10) as client:
            for _ in range(60):
                assert process.poll() is None, 'Production launcher exited'
                try:
                    health = (await client.get('/api/health')).raise_for_status().json()
                    assert health['architecture'] == 'unidirectional-passive-monitoring'
                    (await client.get('/monitor')).raise_for_status()
                    break
                except httpx.HTTPError:
                    await asyncio.sleep(.5)
            else:
                raise RuntimeError('Production readiness timeout')
            result = await verify(client, expected, resume=resume)
            save(f'{label}-result.json', result)
            save('browser-ready.json', dict(lifetime=label, url=BASE + '/monitor', records=30))
            print('BROWSER_READY', label, flush=True)
            deadline = time.monotonic() + 180
            while not (HERE / f'{label}-browser-ack.json').exists():
                if time.monotonic() > deadline:
                    raise TimeoutError('Browser verification not acknowledged')
                await asyncio.sleep(.25)
    finally:
        stop(process, label)
    assert history() == expected
    await asyncio.sleep(1)


async def main():
    expected, before = check_prerequisites()
    await lifetime('first-restart', expected, resume=True)
    await lifetime('second-restart', expected)
    after = {name: sha(ROOT / name) for name in before}
    assert after == before
    save('integrity-after.json', after)
    save('result.json', dict(restart_dod_passed=True, preserved_records=30,
         production_lifetimes_checked=2, full_record_equality=True,
         resumed_records=15, duplicate_resume_records=0, original_files_unchanged=len(after),
         new_ingest_events=0, detector_quality_reevaluated=False, release_ready=False))
    print('RESTART_COMPLETION_PASS', flush=True)


if __name__ == '__main__':
    asyncio.run(main())

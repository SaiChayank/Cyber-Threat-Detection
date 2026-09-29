"""Isolated loopback API -> SQLite -> SSE measurement; never writes demo history.

Run python -m benchmarks.delivery. Starts an owned local API with a temporary
database. No monitored host, frontend, capture source or public service is queried.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
DELIVERY_TARGET_MS = 1000


def p95(values):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * .95))]


async def measure(url, count):
    sent, received, accepted, post_durations = {}, {}, {}, []
    ready = asyncio.Event()
    async with httpx.AsyncClient(base_url=url, trust_env=False, timeout=10) as client:
        async def observe():
            try:
                async with client.stream('GET', '/api/stream', timeout=None) as response:
                    response.raise_for_status()
                    ready.set()
                    async for line in response.aiter_lines():
                        if not line.startswith('data: '):
                            continue
                        row = json.loads(line[6:])
                        flow = row['flow_id']
                        if flow in sent and row['threat_class'] == 'DDOS':
                            received[flow] = dict(sequence=row['sequence'], alert_id=row['alert_id'],
                                                  latency_ms=(time.perf_counter() - sent[flow]) * 1000)
                        if len(received) == count:
                            return
            finally:
                ready.set()  # Startup failure must wake the sender too.

        observer = asyncio.create_task(observe())
        try:
            await asyncio.wait_for(ready.wait(), timeout=5)
            if observer.done():
                observer.result()
                raise ValueError('SSE stream ended before ingest began')
            for i in range(count):
                flow = f'delivery-check-{i}'
                # Explicit simulated flow summary, not a raw packet or an attack
                # transmitted over the network. Event-time gaps avoid deduplication.
                body = dict(timestamp=1700000000000 + i * 31000,
                            src_ip=f'192.0.2.{i % 254 + 1}', dst_ip='198.51.100.1',
                            dst_port=443, protocol=17, packets=12000, bytes=720000,
                            flow_id=flow)
                sent[flow] = time.perf_counter()
                response = await client.post('/api/events', json=body)
                response.raise_for_status()
                post_durations.append((time.perf_counter() - sent[flow]) * 1000)
                matches = [row for row in response.json() if row['threat_class'] == 'DDOS']
                if len(matches) != 1 or matches[0]['flow_id'] != flow:
                    raise ValueError('Ingest did not persist exactly one expected DDoS alert')
                accepted[flow] = matches[0]
            await asyncio.wait_for(observer, timeout=10)
        finally:
            observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)

        for flow, row in accepted.items():
            if (received[flow]['sequence'], received[flow]['alert_id']) != (row['sequence'], row['alert_id']):
                raise ValueError('SSE alert does not match persisted ingest response')
        response = await client.get('/api/alerts', params={'limit': 1000})
        response.raise_for_status()
        stored = {(row['sequence'], row['alert_id']) for row in response.json()}
        if not all((row['sequence'], row['alert_id']) in stored for row in accepted.values()):
            raise ValueError('Delivered alert is missing from SQLite history')

        # A disconnected subscriber must resume after its last sequence, rather
        # than replaying everything or silently losing the remaining alert.
        final_row = max(accepted.values(), key=lambda row: row['sequence'])
        async def reconnect():
            async with client.stream('GET', '/api/stream?after=0',
                                     headers={'Last-Event-ID': str(final_row['sequence'] - 1)}) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith('data: '):
                        row = json.loads(line[6:])
                        if row['alert_id'] != final_row['alert_id'] or row['sequence'] != final_row['sequence']:
                            raise ValueError('SSE resume cursor returned the wrong alert')
                        return True
            raise ValueError('SSE resume stream ended without the expected alert')
        resumed = await asyncio.wait_for(reconnect(), timeout=5)
        telemetry = (await client.get('/api/telemetry')).json()
    latencies = [row['latency_ms'] for row in received.values()]
    return dict(events=count, accepted_alerts=len(accepted), delivered_alerts=len(received),
                api_acceptance_p95_ms=p95(post_durations), api_to_sse_p95_ms=p95(latencies),
                api_to_sse_max_ms=max(latencies), delivery_target_ms=DELIVERY_TARGET_MS,
                delivery_pass=p95(latencies) < DELIVERY_TARGET_MS,
                persistence_verified=True, reconnect_resume_verified=resumed,
                telemetry=telemetry)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=int, default=100)
    args = parser.parse_args()
    if not 10 <= args.events <= 500:
        parser.error('Use 10 to 500 simulated events')
    with tempfile.TemporaryDirectory() as directory:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        url = f'http://127.0.0.1:{port}'
        env = os.environ | {'ALERT_DB': str(Path(directory) / 'delivery.sqlite3')}
        log_path = Path(directory) / 'api.log'
        with log_path.open('w', encoding='utf-8') as log:
            process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.main:app',
                                        '--host', '127.0.0.1', '--port', str(port),
                                        '--log-level', 'warning', '--no-access-log'],
                                       cwd=ROOT, env=env, stdout=log, stderr=log,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                with httpx.Client(trust_env=False, timeout=.5) as client:
                    for _ in range(50):
                        if process.poll() is not None:
                            raise RuntimeError('Isolated API exited during startup')
                        try:
                            response = client.get(url + '/api/health')
                            if response.status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(.1)
                    else:
                        raise RuntimeError('Isolated API did not become ready')
                report = asyncio.run(measure(url, args.events))
            except Exception:
                log.flush()
                print(log_path.read_text(encoding='utf-8')[-4000:], file=sys.stderr)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    report.update(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                  scope='Loopback API ingestion, inference, SQLite and direct SSE reception; excludes Next.js proxy, browser rendering, raw capture and concurrent subscribers',
                  workload='100-or-configured-count simulated high-rate flow summaries in an isolated temporary database',
                  python=platform.python_version(), platform=platform.platform(),
                  runtime_source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                         for name in ('backend/application.py', 'detection/pipeline.py',
                                                      'features/extractor.py', 'features/rate_window.py',
                                                      'persistence/store.py')})
    Path(__file__).with_name('delivery_latest.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    if not report['delivery_pass']:
        raise SystemExit('API-to-SSE latency target failed')


if __name__ == '__main__':
    main()

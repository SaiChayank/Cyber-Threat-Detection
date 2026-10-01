"""Isolated loopback API -> SQLite -> SSE measurement; never writes demo history.

Run python -m benchmarks.delivery. Starts an owned local API with a temporary
database. No monitored host, frontend, capture source or public service is queried.
"""
import argparse
import asyncio
import hashlib
import json
import math
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
from persistence.store import AlertStore

ROOT = Path(__file__).resolve().parent.parent
DELIVERY_TARGET_MS = 1000


def percentile(values, fraction):
    if not values:
        raise ValueError('Cannot calculate latency percentile without deliveries')
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * fraction) - 1]


def verify_alerts(accepted, received, stored, expected):
    """Require a one-to-one, whole-record match across ingest, SQLite and SSE."""
    if len(accepted) != expected or len(received) != expected or len(stored) != expected:
        raise ValueError('Alert count differs across API, SQLite and SSE')
    if set(accepted) != set(received) or set(accepted) != set(stored):
        raise ValueError('Alert flow identities differ across API, SQLite and SSE')
    sequences = set()
    alert_ids = set()
    for flow, api_row in accepted.items():
        sse = received[flow]
        if api_row != stored[flow] or api_row != sse['row']:
            raise ValueError(f'Alert data differs across API, SQLite and SSE: {flow}')
        if sse['sse_id'] != str(api_row['sequence']):
            raise ValueError(f'SSE id differs from persisted sequence: {flow}')
        sequences.add(api_row['sequence'])
        alert_ids.add(api_row['alert_id'])
    if len(sequences) != expected or len(alert_ids) != expected:
        raise ValueError('Alert sequences or IDs are not unique')


def record_digest(rows):
    ordered = sorted(rows, key=lambda row: row['sequence'])
    return hashlib.sha256(json.dumps(ordered, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


async def measure(url, count):
    sent, received, accepted, post_durations = {}, {}, {}, []
    ready = asyncio.Event()
    async with httpx.AsyncClient(base_url=url, trust_env=False, timeout=10) as client:
        async def observe():
            try:
                async with client.stream('GET', '/api/stream', timeout=None) as response:
                    response.raise_for_status()
                    ready.set()
                    sse_id = None
                    async for line in response.aiter_lines():
                        if line.startswith('id: '):
                            sse_id = line[4:]
                            continue
                        if not line.startswith('data: '):
                            continue
                        row = json.loads(line[6:])
                        flow = row['flow_id']
                        if flow not in sent or row['threat_class'] != 'DDOS':
                            raise ValueError('Unexpected SSE alert in isolated benchmark')
                        if flow in received:
                            raise ValueError('Duplicate SSE alert in isolated benchmark')
                        received[flow] = dict(row=row, sse_id=sse_id,
                                              latency_ms=(time.perf_counter() - sent[flow]) * 1000)
                        sse_id = None
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
                rows = response.json()
                if len(rows) != 1 or rows[0]['threat_class'] != 'DDOS' or rows[0]['flow_id'] != flow:
                    raise ValueError('Ingest did not persist exactly one expected DDoS alert')
                accepted[flow] = rows[0]
            await asyncio.wait_for(observer, timeout=10)
        finally:
            observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)

        response = await client.get('/api/alerts', params={'limit': 1000})
        response.raise_for_status()
        stored_rows = response.json()
        stored = {row['flow_id']: row for row in stored_rows}
        if len(stored) != len(stored_rows):
            raise ValueError('Duplicate flow identity in persisted alerts')
        verify_alerts(accepted, received, stored, count)

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
    return dict(events=count, accepted_alerts=len(accepted), persisted_alerts=len(stored),
                delivered_alerts=len(received), success_count=len(received),
                persisted_records_sha256=record_digest(stored_rows),
                api_acceptance_p95_ms=percentile(post_durations, .95),
                api_to_sse_p50_ms=percentile(latencies, .50),
                api_to_sse_p95_ms=percentile(latencies, .95),
                api_to_sse_p99_ms=percentile(latencies, .99),
                api_to_sse_max_ms=max(latencies), delivery_target_ms=DELIVERY_TARGET_MS,
                delivery_pass=percentile(latencies, .95) < DELIVERY_TARGET_MS,
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
        reopened = AlertStore(Path(directory) / 'delivery.sqlite3')
        try:
            durable_rows = reopened.list(limit=1000)
        finally:
            reopened.close()
        if (len(durable_rows) != args.events or
                record_digest(durable_rows) != report['persisted_records_sha256']):
            raise ValueError('SQLite alert history changed or disappeared after API shutdown')
        report['durable_persistence_verified'] = True
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

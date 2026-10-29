"""Local analyst API; separate from the passive capture path."""
import asyncio
import json
import logging
import os
import sqlite3
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse
from pydantic import BaseModel, Field
from detection.pipeline import Pipeline
from ingest.flow_export import FlowExportDecoder, read_flow_export
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader, validate_capture_header
from persistence.store import AlertStore
from replay.scenarios import CLASSES, mixed_demo, scenario
from schemas.traffic_event import TrafficEvent
from datasets.replay import PRESETS, available, records as public_records

# SQLite INTEGER PRIMARY KEY sequences are signed 64-bit values.
MAX_ALERT_SEQUENCE = (1 << 63) - 1

@asynccontextmanager
async def lifespan(app):
    app.state.pipeline = Pipeline()
    app.state.store = AlertStore(os.getenv('ALERT_DB', 'data/alerts.sqlite3'))
    app.state.replay_task = None
    app.state.pending_replay_source = None
    app.state.replay_status = 'idle'
    app.state.replay_error = None
    yield
    await stop()
    app.state.store.close()

app = FastAPI(title='PS26145 Cyber Threat Detection API', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:3000', 'http://127.0.0.1:3000'], allow_methods=['GET', 'POST'], allow_headers=['Content-Type'])

def consume(event):
    return app.state.pipeline.process(event, persist=app.state.store.append_many)

def read_alert_history(read, *args):
    try:
        return read(*args)
    except sqlite3.Error as exc:
        logging.getLogger(__name__).exception('Alert history read failed')
        raise HTTPException(503, 'Alert history temporarily unavailable; retry after storage recovery') from exc

@app.get('/api/health')
async def health():
    return dict(status='online', architecture='unidirectional-passive-monitoring', threat_classes=CLASSES[1:])

@app.get('/api/datasets')
async def datasets():
    return available()

@app.get('/api/benchmark')
async def benchmark():
    path = Path(__file__).resolve().parent.parent / 'benchmarks' / 'latest.json'
    if not path.is_file():
        raise HTTPException(404, 'No saved benchmark; run python -m benchmarks.run')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise HTTPException(503, 'Saved benchmark is unreadable') from exc

@app.get('/api/telemetry')
async def telemetry():
    return app.state.pipeline.telemetry() | dict(replay_status=app.state.replay_status, replay_error=app.state.replay_error, alerts_by_class=read_alert_history(app.state.store.summary), throughput_target=2000, confidence_note='Model score or heuristic strength; not real-world calibrated')

@app.get('/api/alerts')
async def alerts(after: int = Query(0, ge=0, le=MAX_ALERT_SEQUENCE), limit: int = Query(200, ge=1, le=1000), threat: str | None = None, newest: bool = False):
    return read_alert_history(app.state.store.list, after, limit, threat, newest)

@app.post('/api/events')
async def events(event: TrafficEvent):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'Stop replay before ingesting another stream')
    try:
        return consume(event)
    except Exception as exc:
        logging.getLogger(__name__).exception('Event processing failed; causal state was not committed')
        raise HTTPException(503, 'Event processing failed; retry the same event after recovery') from exc

@app.get('/api/stream')
async def stream(request: Request, after: int = Query(0, ge=0, le=MAX_ALERT_SEQUENCE)):
    try:
        last_id = int(request.headers.get('last-event-id', '0'))
        if last_id > MAX_ALERT_SEQUENCE:
            raise HTTPException(422, 'Last-Event-ID exceeds the supported alert sequence range')
        after = max(after, last_id)
    except ValueError:
        pass
    # Fail before successful SSE headers if durable history cannot be read.
    initial_rows = read_alert_history(app.state.store.list, after, 100)
    async def generate():
        cursor = after
        rows = initial_rows
        while not await request.is_disconnected():
            for row in rows:
                cursor = row['sequence']
                yield f'id: {cursor}\ndata: {json.dumps(row)}\n\n'
            if not rows:
                yield ': heartbeat\n\n'
            await asyncio.sleep(.25)
            try:
                rows = app.state.store.list(cursor, 100)
            except sqlite3.Error:
                # Headers have started: close so EventSource can resume from its
                # last delivered ID. SQLite remains the source of truth.
                logging.getLogger(__name__).exception('Alert stream history read failed; closing for resume')
                return
    return StreamingResponse(generate(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache, no-transform', 'X-Accel-Buffering': 'no'})

class ReplayConfig(BaseModel):
    scenario: str = 'ALL'
    speed: float = Field(default=20, ge=.1, le=10000)


def cleanup_replay_source(records, cleanup):
    try:
        if hasattr(records, 'close'):
            records.close()
    finally:
        if cleanup:
            cleanup()


PUBLIC_CAPTURE_ERRORS = frozenset({
    'PCAP requires a complete 24-byte header',
    'Unsupported capture format; upload classic Ethernet PCAP',
    'Only PCAP v2.4 Ethernet captures are supported',
    'Invalid PCAP snap length',
    'PCAPNG requires a complete section header',
    'Invalid PCAPNG block',
    'Truncated PCAPNG block',
    'Only Ethernet captures are supported',
    'Truncated PCAP packet header',
    'Invalid PCAP packet length',
    'Uploaded capture contains a truncated packet',
    'Public capture contains a truncated packet',
})


def public_replay_error(exc):
    # Only these fixed parser diagnostics are intended for analyst display.
    # Arbitrary ValueError text (including validation objects) is still private.
    if type(exc) is ValueError and str(exc) in PUBLIC_CAPTURE_ERRORS:
        return str(exc)
    if isinstance(exc, sqlite3.Error):
        return 'Replay storage unavailable; retry after storage recovery'
    if isinstance(exc, OSError):
        return 'Replay source unavailable; check local storage and retry'
    return 'Replay processing failed; check backend logs and retry'


def report_replay_cleanup_error(exc):
    logging.getLogger(__name__).error('Replay source cleanup failed',
                                    exc_info=(type(exc), exc, exc.__traceback__))
    app.state.replay_status = 'failed'
    detail = 'Replay cleanup failed; check backend logs before retrying'
    app.state.replay_error = f'{app.state.replay_error}; {detail}' if app.state.replay_error else detail


async def run_replay(records, speed, cleanup=None):
    # Stop can cancel a newly scheduled task before this coroutine ever runs.
    # Once entered, this coroutine owns source cleanup in its finally block.
    app.state.pending_replay_source = None
    previous = None
    try:
        for event in records:
            if previous is not None:
                await asyncio.sleep(max(0, (event.timestamp - previous) / 1000 / speed))
            consume(event)
            previous = event.timestamp
        app.state.replay_status = 'complete'
    except asyncio.CancelledError:
        app.state.replay_status = 'stopped'
        raise
    except Exception as exc:
        logging.getLogger(__name__).exception('Replay processing failed')
        app.state.replay_status = 'failed'
        app.state.replay_error = public_replay_error(exc)
    finally:
        try:
            cleanup_replay_source(records, cleanup)
        except Exception as exc:
            report_replay_cleanup_error(exc)

def start_replay(records, speed, cleanup=None):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'A replay is already running')
    app.state.pipeline = Pipeline()
    app.state.replay_status = 'running'
    app.state.replay_error = None
    app.state.pending_replay_source = (records, cleanup)
    app.state.replay_task = asyncio.create_task(run_replay(records, speed, cleanup))
    return {'status': 'running'}

@app.post('/api/replay/start')
async def replay(config: ReplayConfig):
    if config.scenario in PRESETS:
        if not next(item for item in available() if item['id'] == config.scenario)['ready']:
            raise HTTPException(422, 'Dataset not prepared; see docs/DATASETS.md')
        return start_replay(public_records(config.scenario), config.speed)
    if config.scenario != 'ALL' and config.scenario not in CLASSES:
        raise HTTPException(422, 'Unknown scenario')
    records = mixed_demo() if config.scenario == 'ALL' else scenario(config.scenario, seed=100)
    return start_replay(records, config.speed)

@app.post('/api/replay/stop')
async def stop():
    task = app.state.replay_task
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        if app.state.replay_status == 'running':
            # Cancellation before the task's first instruction skips its
            # CancelledError handler and finally block entirely.
            app.state.replay_status = 'stopped'
            pending = app.state.pending_replay_source
            app.state.pending_replay_source = None
            if pending is not None:
                records, cleanup = pending
                try:
                    cleanup_replay_source(records, cleanup)
                except Exception as exc:
                    report_replay_cleanup_error(exc)
    return {'status': app.state.replay_status}

@app.post('/api/replay/pcap')
async def pcap(request: Request, speed: float = Query(20, ge=.1, le=10000),
               source: Literal['packets', 'flow_export'] = Query('packets')):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'A replay is already running')
    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as file:
            path = Path(file.name)
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 16 * 1024 * 1024:
                    raise HTTPException(413, 'PCAP upload limit is 16 MiB')
                file.write(chunk)
    except BaseException as exc:
        if path is not None:
            path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            logging.getLogger(__name__).exception('PCAP upload temporary storage failed')
            raise HTTPException(503, 'Temporary capture storage unavailable; retry after storage recovery') from exc
        raise
    def records():
        try:
            if source == 'flow_export':
                # Received NetFlow/IPFIX/sFlow datagrams; nothing is sent to exporters.
                yield from read_flow_export(path, FlowExportDecoder())
                return
            reader = PcapReader()
            for batch in reader.read_packets(path):
                for flow, dns, tls in batch:
                    yield from_packet(flow, dns, tls)
            if reader.parser.dlq.truncated_packet_count:
                raise ValueError('Uploaded capture contains a truncated packet')
        finally:
            path.unlink(missing_ok=True)
    try:
        with path.open('rb') as capture:
            validate_capture_header(capture.read(32))
        return start_replay(records(), speed, lambda: path.unlink(missing_ok=True))
    except (ValueError, OSError) as exc:
        path.unlink(missing_ok=True)
        logging.getLogger(__name__).exception('Uploaded capture validation failed')
        status = 422 if type(exc) is ValueError and str(exc) in PUBLIC_CAPTURE_ERRORS else 503
        raise HTTPException(status, public_replay_error(exc)) from exc
    except BaseException:
        path.unlink(missing_ok=True)
        raise

@app.get('/', include_in_schema=False)
async def dashboard():
    return RedirectResponse(f"http://localhost:{os.getenv('WEB_PORT', '3000')}", status_code=307)

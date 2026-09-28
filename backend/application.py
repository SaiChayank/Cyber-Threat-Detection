"""Local analyst API; separate from the passive capture path."""
import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader, validate_header
from persistence.store import AlertStore
from replay.scenarios import CLASSES, mixed_demo, scenario
from schemas.traffic_event import TrafficEvent
from datasets.replay import PRESETS, available, records as public_records

@asynccontextmanager
async def lifespan(app):
    app.state.pipeline = Pipeline()
    app.state.store = AlertStore(os.getenv('ALERT_DB', 'data/alerts.sqlite3'))
    app.state.replay_task = None
    app.state.replay_status = 'idle'
    app.state.replay_error = None
    yield
    await stop()
    app.state.store.close()

app = FastAPI(title='PS26145 Cyber Threat Detection API', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'], allow_methods=['GET', 'POST'], allow_headers=['Content-Type'])

def consume(event):
    return [app.state.store.append(a) for a in app.state.pipeline.process(event)]

@app.get('/api/health')
async def health():
    return dict(status='online', architecture='unidirectional-passive-monitoring', threat_classes=CLASSES[1:])

@app.get('/api/datasets')
async def datasets():
    return available()

@app.get('/api/telemetry')
async def telemetry():
    return app.state.pipeline.telemetry() | dict(replay_status=app.state.replay_status, replay_error=app.state.replay_error, alerts_by_class=app.state.store.summary(), throughput_target=2000, confidence_note='Synthetic model posterior or heuristic strength; not real-world calibrated')

@app.get('/api/alerts')
async def alerts(after: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000), threat: str | None = None, newest: bool = False):
    return app.state.store.list(after, limit, threat, newest)

@app.post('/api/events')
async def events(event: TrafficEvent):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'Stop replay before ingesting another stream')
    return consume(event)

@app.get('/api/stream')
async def stream(request: Request, after: int = Query(0, ge=0)):
    try:
        after = max(after, int(request.headers.get('last-event-id', '0')))
    except ValueError:
        pass
    async def generate():
        cursor = after
        while not await request.is_disconnected():
            rows = app.state.store.list(cursor, 100)
            for row in rows:
                cursor = row['sequence']
                yield f'id: {cursor}\ndata: {json.dumps(row)}\n\n'
            if not rows:
                yield ': heartbeat\n\n'
            await asyncio.sleep(.25)
    return StreamingResponse(generate(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache'})

class ReplayConfig(BaseModel):
    scenario: str = 'ALL'
    speed: float = Field(default=20, ge=.1, le=10000)

async def run_replay(records, speed, cleanup=None):
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
        app.state.replay_status = 'failed'
        app.state.replay_error = str(exc)
    finally:
        if hasattr(records, 'close'):
            records.close()
        if cleanup:
            cleanup()

def start_replay(records, speed, cleanup=None):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'A replay is already running')
    app.state.pipeline = Pipeline()
    app.state.replay_status = 'running'
    app.state.replay_error = None
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
    return {'status': app.state.replay_status}

@app.post('/api/replay/pcap')
async def pcap(request: Request, speed: float = Query(20, ge=.1, le=10000)):
    if app.state.replay_status == 'running':
        raise HTTPException(409, 'A replay is already running')
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as file:
        path = Path(file.name)
        size = 0
        try:
            async for chunk in request.stream():
                size += len(chunk)
                if size > 16 * 1024 * 1024:
                    raise HTTPException(413, 'PCAP upload limit is 16 MiB')
                file.write(chunk)
        except BaseException:
            file.close()
            path.unlink(missing_ok=True)
            raise
    def records():
        try:
            for batch in PcapReader().read_packets(path):
                for flow, dns, tls in batch:
                    yield from_packet(flow, dns, tls)
        finally:
            path.unlink(missing_ok=True)
    try:
        with path.open('rb') as capture:
            validate_header(capture.read(24))
        return start_replay(records(), speed, lambda: path.unlink(missing_ok=True))
    except (ValueError, OSError) as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(422, str(exc)) from exc
    except BaseException:
        path.unlink(missing_ok=True)
        raise

dist = Path(__file__).resolve().parent.parent / 'frontend' / 'dist'
if dist.exists():
    app.mount('/assets', StaticFiles(directory=dist / 'assets'), name='assets')
    @app.get('/')
    async def dashboard():
        return FileResponse(dist / 'index.html')

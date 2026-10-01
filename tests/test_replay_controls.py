"""Replay control-state integration; analyst history stays in isolated SQLite."""
import asyncio
import struct
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient

import backend.application as application
import datasets.replay as public_replay
from detection.pipeline import Pipeline
from persistence.store import AlertStore


START = 1_700_000_000_000


def alert_event(index):
    return dict(timestamp=START + index * 31_000,
                src_ip=f'192.0.2.{index + 1}', dst_ip='198.51.100.1',
                dst_port=443, protocol=17, packets=12_000, bytes=720_000,
                flow_id=f'replay-control-{index}')


def await_replay(client):
    client.portal.call(lambda: application.app.state.replay_task)
    return client.get('/api/telemetry').json()


def wait_until_processed(client, minimum=1):
    for _ in range(100):
        state = client.get('/api/telemetry').json()
        if state['processed'] >= minimum:
            return state
        time.sleep(.01)
    raise AssertionError('Replay did not process an incremental event')


def test_scenario_start_conflict_stop_restart_and_completion(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'controls.sqlite3'))
    with TestClient(application.app) as client:
        original = client.post('/api/events', json=alert_event(0)).json()
        assert len(original) == 1
        assert client.post('/api/replay/start', json={'scenario': 'BOTNET_C2', 'speed': .1}).json() == {'status': 'running'}
        running = wait_until_processed(client)
        assert running['replay_status'] == 'running'
        assert 1 <= running['processed'] < 32
        assert client.post('/api/replay/start', json={'scenario': 'DDOS', 'speed': 1}).status_code == 409
        assert client.post('/api/events', json=alert_event(1)).status_code == 409

        stopped = client.post('/api/replay/stop').json()
        assert stopped == {'status': 'stopped'}
        processed = client.get('/api/telemetry').json()['processed']
        time.sleep(.05)
        assert client.get('/api/telemetry').json()['processed'] == processed
        assert application.app.state.replay_task.done()
        assert client.get('/api/alerts').json() == original

        assert client.post('/api/replay/start', json={'scenario': 'BOTNET_C2', 'speed': 10000}).status_code == 200
        completed = await_replay(client)
        assert completed['replay_status'] == 'complete'
        assert completed['replay_error'] is None
        assert completed['processed'] == 32
        assert client.get('/api/alerts').json()[0] == original[0]
        assert client.post('/api/replay/stop').json() == {'status': 'complete'}
        for speed in (.09, 10000.01, -1):
            assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': speed}).status_code == 422


def test_missing_and_malformed_public_preset_reports_error_without_history_loss(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'public.sqlite3'))
    monkeypatch.setattr(public_replay, 'ROOT', tmp_path)
    monkeypatch.setitem(public_replay.PRESETS, 'PUBLIC_TEST_MISSING', ('missing', 'missing.pcap'))
    monkeypatch.setitem(public_replay.PRESETS, 'PUBLIC_TEST_BROKEN', ('broken', 'broken.pcap'))
    monkeypatch.setitem(public_replay.PRESETS, 'PUBLIC_TEST_TRUNCATED', ('truncated', 'truncated.pcap'))
    (tmp_path / 'broken.pcap').write_bytes(b'not a complete pcap')
    header = struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack('!IIII', 1_700_000_000, 0, 40, 40)
    (tmp_path / 'truncated.pcap').write_bytes(header + packet_header + b'abc')
    with TestClient(application.app) as client:
        original = client.post('/api/events', json=alert_event(0)).json()
        assert client.post('/api/replay/start', json={'scenario': 'PUBLIC_TEST_MISSING'}).status_code == 422
        assert client.get('/api/telemetry').json()['replay_status'] == 'idle'
        assert client.get('/api/alerts').json() == original

        assert client.post('/api/replay/start', json={'scenario': 'PUBLIC_TEST_BROKEN'}).json() == {'status': 'running'}
        failed = await_replay(client)
        assert failed['replay_status'] == 'failed'
        assert 'complete 24-byte header' in failed['replay_error']
        assert client.get('/api/alerts').json() == original

        assert client.post('/api/replay/start', json={'scenario': 'PUBLIC_TEST_TRUNCATED'}).status_code == 200
        truncated = await_replay(client)
        assert truncated['replay_status'] == 'failed'
        assert 'truncated' in truncated['replay_error'].lower()
        assert client.get('/api/alerts').json() == original
        assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': 10000}).status_code == 200
        recovered = await_replay(client)
        assert recovered['replay_status'] == 'complete'
        assert recovered['replay_error'] is None
        assert recovered['processed'] == 32
        assert client.get('/api/alerts').json()[0] == original[0]


def test_runtime_failure_keeps_committed_alerts_and_next_replay_starts_cleanly(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'runtime.sqlite3'))
    with TestClient(application.app) as client:
        original = client.post('/api/events', json=alert_event(0)).json()[0]

        def broken_scenario(*_args, **_kwargs):
            from schemas.traffic_event import TrafficEvent
            yield TrafficEvent(**alert_event(1))
            raise RuntimeError('controlled replay source failure')

        with monkeypatch.context() as patch:
            patch.setattr(application, 'scenario', broken_scenario)
            assert client.post('/api/replay/start', json={'scenario': 'BENIGN', 'speed': 10000}).status_code == 200
            failed = await_replay(client)
        assert failed['replay_status'] == 'failed'
        assert failed['replay_error'] == 'controlled replay source failure'
        assert failed['processed'] == 1
        saved = client.get('/api/alerts').json()
        assert len(saved) == 2 and saved[0] == original
        assert saved[1]['flow_id'] == 'replay-control-1'

        assert client.post('/api/replay/start', json={'scenario': 'DDOS', 'speed': 10000}).status_code == 200
        recovered = await_replay(client)
        assert recovered['replay_status'] == 'complete'
        assert recovered['replay_error'] is None
        assert recovered['processed'] == 32
        assert client.get('/api/alerts').json()[:2] == saved


def test_speed_scales_event_time_gaps_without_batching(monkeypatch):
    observed = []
    delays = []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        delays.append(seconds)
        await real_sleep(0)

    with monkeypatch.context() as patch:
        patch.setattr(application, 'consume', observed.append)
        patch.setattr(application.asyncio, 'sleep', fake_sleep)
        application.app.state.replay_status = 'running'
        application.app.state.replay_error = None
        records = [SimpleNamespace(timestamp=START), SimpleNamespace(timestamp=START + 1500),
                   SimpleNamespace(timestamp=START + 3500)]
        asyncio.run(application.run_replay(records, speed=2))

    assert observed == records
    assert delays == [.75, 1.0]
    assert application.app.state.replay_status == 'complete'


def test_immediate_stop_before_replay_task_starts_sets_state_and_cleans_up(tmp_path):
    async def exercise():
        application.app.state.pipeline = Pipeline()
        application.app.state.store = AlertStore(tmp_path / 'immediate.sqlite3')
        application.app.state.replay_status = 'idle'
        application.app.state.replay_task = None
        cleaned = []
        try:
            records = iter(())
            assert application.start_replay(records, 1, lambda: cleaned.append(True)) == {'status': 'running'}
            # No event-loop yield has occurred, so the scheduled task has not run.
            assert await application.stop() == {'status': 'stopped'}
            assert cleaned == [True]
            assert application.app.state.replay_task.done()
        finally:
            application.app.state.store.close()

    asyncio.run(exercise())


def test_cleanup_exception_is_reported_and_runs_remaining_cleanup():
    class BrokenClose:
        def __iter__(self):
            return iter(())

        def close(self):
            raise RuntimeError('controlled source close failure')

    async def exercise():
        cleaned = []
        application.app.state.replay_status = 'running'
        application.app.state.replay_error = None
        await application.run_replay(BrokenClose(), 1, lambda: cleaned.append(True))
        assert cleaned == [True]
        assert application.app.state.replay_status == 'failed'
        assert 'controlled source close failure' in application.app.state.replay_error

    asyncio.run(exercise())

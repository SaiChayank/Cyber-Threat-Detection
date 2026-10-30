"""Failed events must not commit causal state or a partial alert batch."""
import pickle
import sqlite3
import asyncio

import httpx

import pytest
from fastapi.testclient import TestClient

from backend import application
from detection.pipeline import Pipeline
from persistence.store import AlertStore
from replay.demo_pack import stable_alert
from schemas.traffic_event import TrafficEvent
from tests.test_sqlite_restart import ddos_event, stored_alert
from tests.test_sse_resume import local_api, receive


def state(pipeline):
    return pickle.dumps((pipeline.extractor.__dict__, pipeline.processed,
                         pipeline.dedup, pipeline.sessions, list(pipeline.latencies)))


def test_locked_write_is_retryable_without_suppression_or_double_count(tmp_path, monkeypatch):
    database = tmp_path / 'locked.sqlite3'
    monkeypatch.setenv('ALERT_DB', str(database))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        saved = client.post('/api/events', json=ddos_event(0)).json()
        pipeline = application.app.state.pipeline
        before = state(pipeline)
        application.app.state.store.connection.execute('PRAGMA busy_timeout=10')
        locker = sqlite3.connect(database)
        try:
            locker.execute('BEGIN IMMEDIATE')
            response = client.post('/api/events', json=ddos_event(1))
            assert response.status_code == 503
            assert state(pipeline) == before
            assert client.get('/api/alerts').json() == saved
            assert not application.app.state.store.connection.in_transaction
        finally:
            locker.rollback()
            locker.close()
        retried = client.post('/api/events', json=ddos_event(1))
        assert retried.status_code == 200 and len(retried.json()) == 1
        alert = retried.json()[0]
        assert alert['raw_evidence_metrics']['packet_rate'] == 1200
        assert pipeline.processed == 2
        assert len(pipeline.extractor.sources['192.0.2.2']) == 1
        assert client.get('/api/alerts').json() == saved + [alert]
        assert client.post('/api/events', json=ddos_event(2)).status_code == 200


@pytest.mark.parametrize('stage', ['inference', 'feature', 'alert'])
def test_failed_processing_preserves_state_and_retry_matches_baseline(tmp_path, monkeypatch, stage):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'inference.sqlite3'))
    event = ddos_event(0) | {'flow_id': None}
    baseline = Pipeline().process(TrafficEvent(**event))
    with TestClient(application.app, raise_server_exceptions=False) as client:
        pipeline = application.app.state.pipeline
        before = state(pipeline)
        with monkeypatch.context() as patch:
            if stage == 'inference':
                def fail(_features):
                    raise RuntimeError('controlled private inference error')
                patch.setattr(pipeline.model, 'predict', fail)
            elif stage == 'feature':
                # Fail after rate/history mutation, not before feature extraction.
                def fail(*_args):
                    raise RuntimeError('controlled private lexical error')
                patch.setattr('features.extractor.dga_lexical_features', fail)
            else:
                def fail(*_args, **_kwargs):
                    raise RuntimeError('controlled private alert error')
                patch.setattr('detection.pipeline.AlertEvent.create', fail)
            response = client.post('/api/events', json=event)
            assert response.status_code == 503
            assert 'private' not in response.text
            assert state(pipeline) == before
            assert client.get('/api/alerts').json() == []
        retried = client.post('/api/events', json=event)
        assert retried.status_code == 200
        assert [stable_alert(a) for a in retried.json()] == [stable_alert(a) for a in baseline]
        assert pipeline.processed == 1
        assert pipeline.extractor.global_rates.packets == event['packets']
        assert len(pipeline.sessions) == 1


def test_second_alert_insert_failure_rolls_back_whole_event_and_history(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'batch.sqlite3'))
    event = ddos_event(1) | dict(packets=1, bytes=90, dst_port=53, dns_type=16,
        dns_name='q7x9k2z4m6b8v1j3p5d0r2s4w6y8a1c3e5f7g9h0i2l4n6o8u1t3.org')
    with TestClient(application.app, raise_server_exceptions=False) as client:
        saved = client.post('/api/events', json=ddos_event(0)).json()
        pipeline = application.app.state.pipeline
        monkeypatch.setattr(pipeline.model, 'predict', lambda _: ('BENIGN', 1.0))
        before = state(pipeline)
        connection = application.app.state.store.connection
        connection.execute("CREATE TRIGGER fail_second BEFORE INSERT ON alerts "
                           "WHEN NEW.threat = 'DGA_DOMAINS' BEGIN SELECT RAISE(ABORT, 'test insert failure'); END")
        connection.commit()
        assert client.post('/api/events', json=event).status_code == 503
        assert state(pipeline) == before
        assert not connection.in_transaction
        assert client.get('/api/alerts').json() == saved
        connection.execute('DROP TRIGGER fail_second')
        connection.commit()
        result = client.post('/api/events', json=event)
        assert result.status_code == 200
        assert {a['threat_class'] for a in result.json()} == {'DNS_TUNNELLING', 'DGA_DOMAINS'}
        assert [a['sequence'] for a in result.json()] == [2, 3]
        assert client.get('/api/alerts').json() == saved + result.json()


def test_duplicate_id_batch_rolls_back_and_releases_write_transaction(tmp_path):
    store = AlertStore(tmp_path / 'duplicate.sqlite3')
    try:
        saved = store.append(stored_alert('original'))
        with pytest.raises(sqlite3.IntegrityError):
            store.append_many([stored_alert('new'), stored_alert('original')])
        assert not store.connection.in_transaction
        assert store.list() == [saved]
        assert store.append(stored_alert('new'))['sequence'] == 2
        with pytest.raises(sqlite3.IntegrityError):
            store.append(stored_alert('original'))
        assert not store.connection.in_transaction
    finally:
        store.close()


@pytest.mark.parametrize('protocol', [6, 17])
@pytest.mark.parametrize('case', ['same_bucket', 'expiration', 'eviction'])
def test_failure_rolls_back_expiration_overflow_and_lru_eviction(protocol, case):
    pipeline = Pipeline()
    pipeline.extractor.max_sources = 2
    pipeline.extractor.max_events = 2
    pipeline.extractor.global_rates.max_sources = 1
    for i in range(4):
        event = TrafficEvent(**(ddos_event(0) | dict(timestamp=1_700_000_000_000 + i * 1000,
                            src_ip=f'192.0.2.{1 + i % 2}', protocol=protocol)))
        pipeline.process(event)
    before = state(pipeline)
    event = TrafficEvent(**(ddos_event(3) | dict(protocol=protocol, flow_id=None)))
    if case == 'same_bucket':
        event = event.model_copy(update={'timestamp': 1_700_000_003_000, 'src_ip': event.src_ip.__class__('192.0.2.2')})
    elif case == 'expiration':
        event = event.model_copy(update={'src_ip': event.src_ip.__class__('192.0.2.2')})
    def fail(_alerts):
        raise sqlite3.OperationalError('controlled write failure')
    with pytest.raises(sqlite3.OperationalError):
        pipeline.process(event, persist=fail)
    assert state(pipeline) == before
    pipeline.process(event)
    assert pipeline.processed == 5
    assert pipeline.extractor.global_rates.packets == event.packets * (5 if case == 'same_bucket' else 1)
    assert len(pipeline.extractor.sources) == 2


def test_failed_high_timestamp_does_not_make_retry_or_next_event_late():
    pipeline = Pipeline()
    event = TrafficEvent(**ddos_event(0))
    pipeline.process(event)
    before = state(pipeline)
    def fail(_alerts):
        raise sqlite3.OperationalError('controlled write failure')
    with pytest.raises(sqlite3.OperationalError):
        pipeline.process(TrafficEvent(**ddos_event(3)), persist=fail)
    assert state(pipeline) == before
    pipeline.process(TrafficEvent(**ddos_event(1)))
    assert pipeline.processed == 2 and pipeline.extractor.late_events == 0


def test_serialization_failure_after_first_insert_rolls_back_batch(tmp_path):
    store = AlertStore(tmp_path / 'serialize.sqlite3')
    try:
        saved = store.append(stored_alert('original'))
        invalid = stored_alert('invalid')
        invalid.raw_evidence_metrics = {'not_json': object()}
        with pytest.raises(TypeError):
            store.append_many([stored_alert('new'), invalid])
        assert not store.connection.in_transaction
        assert store.list() == [saved]
        assert store.append(stored_alert('new'))['sequence'] == 2
    finally:
        store.close()


def test_locked_api_retry_is_delivered_once_via_sse_and_survives_restart(tmp_path):
    database = tmp_path / 'sse-retry.sqlite3'
    with local_api(database) as base:
        with httpx.Client(base_url=base, trust_env=False, timeout=10) as client:
            locker = sqlite3.connect(database)
            try:
                locker.execute('BEGIN IMMEDIATE')
                assert client.post('/api/events', json=ddos_event(0)).status_code == 503
                assert client.get('/api/alerts').json() == []
                assert client.get('/api/telemetry').json()['processed'] == 0
            finally:
                locker.rollback()
                locker.close()
            result = client.post('/api/events', json=ddos_event(0))
            result.raise_for_status()
            saved = result.json()
            assert len(saved) == 1
            assert client.post('/api/events', json=ddos_event(0)).json() == []
        async def delivered():
            async with httpx.AsyncClient(base_url=base, trust_env=False) as client:
                return await asyncio.wait_for(receive(client, 1), 5)
        assert asyncio.run(delivered()) == saved
    with local_api(database) as base:
        with httpx.Client(base_url=base, trust_env=False) as client:
            assert client.get('/api/alerts').json() == saved


def test_processing_telemetry_keeps_excluding_persistence_time(monkeypatch):
    pipeline = Pipeline()
    clock = [10.0]
    monkeypatch.setattr('detection.pipeline.time.perf_counter', lambda: clock[0])
    def predict(_features):
        clock[0] += .125
        return 'BENIGN', 1.0
    def persist(alerts):
        clock[0] += 5
        return alerts
    monkeypatch.setattr(pipeline.model, 'predict', predict)
    pipeline.process(TrafficEvent(**ddos_event(0)), persist=persist)
    assert list(pipeline.latencies) == [125.0]

"""SQLite is the durable, ordered source of analyst alert history."""
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.application import app
from persistence.store import AlertStore
from schemas.alert import AlertEvent
from tests.test_sse_resume import local_api


START = 1_700_000_000_000


def ddos_event(index):
    return dict(timestamp=START + index * 31_000,
                src_ip=f'192.0.2.{index + 1}', dst_ip='198.51.100.1',
                dst_port=443, protocol=17, packets=12_000, bytes=720_000,
                flow_id=f'sqlite-restart-{index}')


def dga_event(index):
    return dict(timestamp=START + index * 31_000,
                src_ip='192.0.2.40', dst_ip='198.51.100.53',
                dst_port=53, protocol=17, packets=1, bytes=90,
                dns_name='q7x9k2z4m6b8v1j3p5d0r2s4w6.example.org',
                flow_id=f'sqlite-dga-{index}')


def stored_alert(alert_id, threat='DDOS'):
    return AlertEvent(timestamp=START, flow_id=f'flow-{alert_id}', threat_class=threat,
                      confidence_score=.8, severity='HIGH', supporting_evidence='observed metadata',
                      alert_id=alert_id, src_ip='192.0.2.1', dst_ip='198.51.100.1',
                      src_port=49152, dst_port=443, protocol=17, detection_source='RULE',
                      raw_evidence_metrics={'packet_rate': 1200})


def test_empty_database_and_api_restart_preserve_order_pages_and_filter(tmp_path, monkeypatch):
    database = tmp_path / 'analyst.sqlite3'
    monkeypatch.setenv('ALERT_DB', str(database))
    with TestClient(app) as client:
        assert client.get('/api/alerts').json() == []
        assert client.get('/api/alerts?newest=true').json() == []
        assert client.get('/api/telemetry').json()['alerts_by_class'] == {}
        posted = []
        for index in range(3):
            response = client.post('/api/events', json=ddos_event(index))
            assert response.status_code == 200
            assert len(response.json()) == 1 and response.json()[0]['threat_class'] == 'DDOS'
            posted.extend(response.json())
        response = client.post('/api/events', json=dga_event(3))
        assert response.status_code == 200
        assert len(response.json()) == 1 and response.json()[0]['threat_class'] == 'DGA_DOMAINS'
        posted.extend(response.json())
        assert [row['sequence'] for row in posted] == [1, 2, 3, 4]

    # A fresh application lifespan opens the same file, not a replacement store.
    with TestClient(app) as client:
        assert client.get('/api/alerts?limit=1000').json() == posted
        first = client.get('/api/alerts?limit=2').json()
        second = client.get(f"/api/alerts?limit=2&after={first[-1]['sequence']}").json()
        assert first + second == posted
        assert client.get('/api/alerts?after=4').json() == []
        assert client.get('/api/alerts?newest=true&limit=2').json() == posted[-2:][::-1]
        assert client.get('/api/alerts?threat=DDOS').json() == posted[:3]
        assert client.get('/api/alerts?threat=DGA_DOMAINS').json() == posted[3:]
        assert client.get('/api/alerts?threat=NOT_A_THREAT').json() == []
        assert client.get("/api/alerts?threat=DDOS%27%20OR%201%3D1").json() == []
        assert client.get('/api/alerts?limit=0').status_code == 422
        assert client.get('/api/alerts?limit=1001').status_code == 422
        assert client.get('/api/alerts?after=-1').status_code == 422
        assert client.get('/api/telemetry').json()['alerts_by_class'] == {'DDOS': 3, 'DGA_DOMAINS': 1}
        response = client.post('/api/events', json=ddos_event(4))
        assert response.status_code == 200 and len(response.json()) == 1
        continued = response.json()[0]
        assert continued['sequence'] == 5
        assert len({row['alert_id'] for row in posted + [continued]}) == 5
        assert client.get('/api/alerts?after=4').json() == [continued]

    reopened = AlertStore(database)
    try:
        assert reopened.list(limit=1000) == posted + [continued]
    finally:
        reopened.close()


def test_duplicate_alert_id_is_rejected_without_overwriting_history(tmp_path):
    database = tmp_path / 'duplicates.sqlite3'
    store = AlertStore(database)
    try:
        first = store.append(stored_alert('same-id'))
        with pytest.raises(sqlite3.IntegrityError):
            store.append(stored_alert('same-id', threat='DGA_DOMAINS'))
        assert store.list() == [first]
        next_row = store.append(stored_alert('new-id'))
        assert next_row['sequence'] > first['sequence']
        assert store.list() == [first, next_row]
    finally:
        store.close()
    reopened = AlertStore(database)
    try:
        assert reopened.list() == [first, next_row]
        assert reopened.summary() == {'DDOS': 2}
    finally:
        reopened.close()


def test_alert_records_and_sequence_continue_after_real_api_process_restart(tmp_path):
    database = tmp_path / 'process-restart.sqlite3'
    with local_api(database) as base:
        with httpx.Client(base_url=base, trust_env=False, timeout=5) as client:
            before = []
            for index in range(3):
                response = client.post('/api/events', json=ddos_event(index))
                response.raise_for_status()
                before.extend(response.json())
            assert [row['sequence'] for row in before] == [1, 2, 3]

    with local_api(database) as base:
        with httpx.Client(base_url=base, trust_env=False, timeout=5) as client:
            assert client.get('/api/alerts').json() == before
            response = client.post('/api/events', json=ddos_event(3))
            response.raise_for_status()
            after = response.json()
            assert len(after) == 1 and after[0]['sequence'] == 4
            assert client.get('/api/alerts?limit=2').json() == before[:2]
            assert client.get('/api/alerts?after=2&limit=2').json() == before[2:] + after


def test_corrupt_or_unavailable_database_fails_closed_without_replacing_data(tmp_path, monkeypatch):
    corrupt = tmp_path / 'corrupt.sqlite3'
    original = b'not a sqlite database; retain these bytes'
    corrupt.write_bytes(original)
    with pytest.raises(sqlite3.DatabaseError):
        AlertStore(corrupt)
    assert corrupt.read_bytes() == original

    # Startup must surface the error rather than silently opening a fresh DB.
    monkeypatch.setenv('ALERT_DB', str(corrupt))
    with pytest.raises(sqlite3.DatabaseError):
        with TestClient(app):
            pass
    assert corrupt.read_bytes() == original

    unavailable = tmp_path / 'unavailable-directory'
    unavailable.mkdir()
    with pytest.raises(sqlite3.OperationalError):
        AlertStore(unavailable)
    assert unavailable.is_dir()

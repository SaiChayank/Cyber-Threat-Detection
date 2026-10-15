import json
import shutil
import pytest
from fastapi.testclient import TestClient

from backend import application
from replay.demo_pack import MANIFEST, ROOT, sha256, stable_alert, verify
from replay.scenarios import CLASSES


def test_frozen_pack_repeats_without_network_or_persistence(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError('Offline demo attempted network access')

    monkeypatch.setattr(socket, 'socket', forbidden)
    first = verify()
    assert verify() == first
    assert first['passed']
    assert len(first['results']) == 9
    assert sum(row['events'] for row in first['results']) == 512
    assert sum(row['alert_count'] for row in first['results']) == 30


def test_stable_alert_excludes_only_delivery_identity_and_rounds_metrics():
    first = dict(alert_id='one', created_at_ms=100, sequence=1,
                 flow_id='flow', supporting_evidence='observed',
                 raw_evidence_metrics={'ratio': 1.123456789111, 'missing': None})
    second = first | dict(alert_id='two', created_at_ms=200, sequence=2)
    assert stable_alert(first) == stable_alert(second)
    assert stable_alert(first)['raw_evidence_metrics'] == {'ratio': 1.123456789, 'missing': None}
    assert stable_alert(first) != stable_alert(second | {'supporting_evidence': 'changed'})
    assert first['alert_id'] == 'one'  # Projection never mutates the original.


@pytest.mark.parametrize('failure', ['manifest', 'artifact', 'source', 'expected'])
def test_preflight_fails_closed_on_changed_pin_or_output(tmp_path, failure):
    manifest = json.loads(MANIFEST.read_text())
    copy = tmp_path / 'manifest.json'
    copy.write_bytes(MANIFEST.read_bytes())
    copy.with_suffix('.sha256').write_text(sha256(copy))
    root = ROOT
    if failure == 'manifest':
        copy.write_bytes(copy.read_bytes() + b' ')
        error = 'manifest SHA256 mismatch'
    elif failure == 'artifact':
        root = tmp_path
        manifest['provenance'] = {}
        target = root / manifest['scenarios'][0]['artifact']
        target.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / manifest['scenarios'][0]['artifact'], target)
        target.write_bytes(target.read_bytes() + b' ')
        error = 'artifact SHA256 mismatch'
    elif failure == 'source':
        name = next(iter(manifest['provenance']))
        manifest['provenance'][name]['sha256'] = '0' * 64
        error = 'provenance SHA256 mismatch'
    else:
        manifest['scenarios'][0]['expected']['alert_count'] = 1
        error = 'alert trace/evidence/timing differs'
    if failure != 'manifest':
        copy.write_text(json.dumps(manifest), encoding='utf-8')
        copy.with_suffix('.sha256').write_text(sha256(copy))
    with pytest.raises(ValueError, match=error):
        verify(copy, root=root)


@pytest.mark.parametrize('preset', CLASSES + ['ALL'])
def test_api_preset_matches_frozen_trace_with_isolated_history(preset, tmp_path, monkeypatch):
    row = next(item for item in json.loads(MANIFEST.read_text())['scenarios'] if item['preset'] == preset)
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'demo.sqlite3'))
    original = application.consume
    positions = {}
    event_count = 0

    def consume(event):
        nonlocal event_count
        event_count += 1
        alerts = original(event)
        for alert in alerts:
            positions.setdefault(alert['threat_class'], (event_count, stable_alert(alert)))
        return alerts

    monkeypatch.setattr(application, 'consume', consume)
    with TestClient(application.app) as client:
        assert client.get('/api/alerts').json() == []
        assert client.post('/api/replay/start', json={'scenario': preset, 'speed': 10000}).status_code == 200
        client.portal.call(lambda: application.app.state.replay_task)
        state = client.get('/api/telemetry').json()
        assert state['replay_status'] == 'complete'
        assert state['replay_error'] is None
        assert event_count == row['expected']['events']
        stored = client.get('/api/alerts').json()
        assert len(stored) == row['expected']['alert_count']
        assert len({alert['alert_id'] for alert in stored}) == len(stored)
        assert list(positions) == list(row['expected']['first_alerts'])
        for label, first in row['expected']['first_alerts'].items():
            assert positions[label] == (first['event_position'], first['alert'])
        # Restarting the same preset resets causal/dedup state without deleting history.
        assert client.post('/api/replay/start', json={'scenario': preset, 'speed': 10000}).status_code == 200
        client.portal.call(lambda: application.app.state.replay_task)
        restarted = client.get('/api/alerts').json()
        count = len(stored)
        assert len(restarted) == count * 2
        assert [stable_alert(alert) for alert in stored] == [stable_alert(alert) for alert in restarted[count:]]

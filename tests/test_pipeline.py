import asyncio
import json
import struct
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from ingest.pcap_reader import PcapReader
from ml.model import Model, ARTIFACT
from persistence.store import AlertStore
from replay.scenarios import CLASSES, scenario
from schemas.traffic_event import TrafficEvent


@pytest.mark.parametrize('label', CLASSES[1:])
def test_required_threat_emits_before_end(label):
    pipeline = Pipeline()
    records = list(scenario(label, seed=100))
    matches = [(i, a) for i, event in enumerate(records) for a in pipeline.process(event) if a.threat_class == label]
    assert matches, label
    assert matches[0][0] < len(records)-1
    body = matches[0][1].to_dict()
    assert {'timestamp', 'flow_id', 'threat_class', 'confidence_score', 'supporting_evidence', 'severity'} <= body.keys()
    assert 0 <= body['confidence_score'] <= 1
    assert body['supporting_evidence']


def test_benign_demo_has_no_alerts():
    pipeline = Pipeline()
    assert not [a for event in scenario('BENIGN', 100) for a in pipeline.process(event)]


@pytest.mark.parametrize('name', ['google.com', 'youtube.com', 'facebook.com',
                                  'baidu.com', 'wikipedia.org', 'mail.company.test'])
def test_normal_domains_do_not_emit_dga_even_with_overconfident_model(name):
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('DGA_DOMAINS', .99999)
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17, dns_name=name)
    assert not [a for a in pipeline.process(event) if a.threat_class == 'DGA_DOMAINS']


def test_domain_length_rule_does_not_count_suffix_as_suspicious_label():
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17,
                         dns_name='q7x9k2z4m6b8.service.example.org', dns_type=16)
    f = FeatureExtractor().update(event)
    assert f['domain_length'] >= 20 and f['domain_label_length'] == 12
    assert f['domain_entropy'] >= 3.5 and f['bigram_surprise'] >= .8
    assert not pipeline.process(event)
    # A long readable suffix cannot manufacture the long-TXT rule either.
    event = event.model_copy(update={'dns_name': 'mail.' + 'service.' * 8 + 'example.org',
                                     'timestamp': event.timestamp + 1000})
    assert not pipeline.process(event)


def test_long_random_txt_query_keeps_both_lexical_alerts_and_evidence():
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    name = 'q7x9k2z4m6b8v1j3p5d0r2s4w6y8a1c3e5f7g9h0i2l4n6o8u1t3' + '.example.org'
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17,
                         dns_name=name, dns_type=16)
    alerts = pipeline.process(event)
    assert {a.threat_class for a in alerts} == {'DGA_DOMAINS', 'DNS_TUNNELLING'}
    for alert in alerts:
        assert alert.raw_evidence_metrics['domain_label_length'] == len(name.split('.')[0])
        assert alert.raw_evidence_metrics['confidence_kind'] == 'heuristic strength'


def test_udp_flood_and_encrypted_sequences_without_fingerprint():
    pipeline = Pipeline()
    flood = [e.model_copy(update={'protocol': 17, 'syn': False, 'dst_port': 53}) for e in scenario('DDOS')]
    assert any(a.threat_class == 'DDOS' for e in flood for a in pipeline.process(e))
    pipeline = Pipeline()
    encrypted = [e.model_copy(update={'tls_fingerprint': None}) for e in scenario('ENCRYPTED_MALWARE')]
    assert any(a.threat_class == 'ENCRYPTED_MALWARE' for e in encrypted for a in pipeline.process(e))


def test_unobserved_reverse_ratio_is_missing():
    event = next(scenario('BENIGN'))
    f = FeatureExtractor().update(event)
    assert f['observed_byte_ratio'] is None
    assert f['reverse_available'] == 0
    with pytest.raises(ValueError):
        TrafficEvent(**(event.model_dump() | {'reverse_bytes': 10}))


def test_session_flow_identity_is_stable_until_idle_timeout():
    pipeline = Pipeline()
    event = next(scenario('BOTNET_C2'))
    first = pipeline.flow_id(event)
    assert pipeline.flow_id(event.model_copy(update={'timestamp': event.timestamp+1000})) == first
    assert pipeline.flow_id(event.model_copy(update={'timestamp': event.timestamp+70000})) != first


def test_valid_pcap_api_runs_incrementally(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'capture.db'))
    header = struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    tcp = struct.pack('!HHIIHHHH', 50000, 80, 1, 0, (5 << 12) | 2, 65535, 0, 0)
    packet = ethernet + ip + tcp
    capture = header + b''.join(struct.pack('!IIII', 1700000000+i, 0, len(packet), len(packet)) + packet for i in range(3))
    with TestClient(app) as client:
        assert client.post('/api/replay/pcap?speed=10000', content=capture).status_code == 200
        client.portal.call(lambda: app.state.replay_task)
        state = client.get('/api/telemetry').json()
        assert state['processed'] == 3
        assert state['replay_status'] == 'complete'


def test_late_events_do_not_modify_history_and_state_is_bounded():
    extractor = FeatureExtractor(max_sources=2, max_events=3)
    events = list(scenario('DDOS'))
    for event in events:
        extractor.update(event)
    assert len(extractor.sources) == 2
    assert extractor.update(events[0]) is None
    assert extractor.late_events == 1


def test_volume_only_exfil_does_not_invent_reverse():
    pipeline = Pipeline()
    records = [e.model_copy(update={'reverse_bytes': None, 'reverse_observed': False}) for e in scenario('DATA_EXFILTRATION')]
    alerts = [a for e in records for a in pipeline.process(e) if a.threat_class == 'DATA_EXFILTRATION']
    assert alerts
    assert all(a.raw_evidence_metrics['observed_byte_ratio'] is None for a in alerts)
    assert all('volume-only' in a.supporting_evidence for a in alerts)


def test_model_integrity_rejects_modified_artifact(tmp_path):
    path = tmp_path / 'model.json'
    path.write_bytes(ARTIFACT.read_bytes()+b' ')
    path.with_suffix('.sha256').write_text(ARTIFACT.with_suffix('.sha256').read_text())
    with pytest.raises(ValueError, match='integrity'):
        Model(path)


def test_persistence_survives_restart(tmp_path):
    path = tmp_path / 'alerts.db'
    pipeline = Pipeline()
    alert = next(a for e in scenario('DGA_DOMAINS') for a in pipeline.process(e))
    store = AlertStore(path)
    store.append(alert)
    store.close()
    store = AlertStore(path)
    assert store.list()[0]['alert_id'] == alert.alert_id
    assert store.list(threat='DDOS') == []
    store.close()


def test_api_validation_replay_and_alert_output(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'api.db'))
    monkeypatch.setenv('WEB_PORT', '3300')
    with TestClient(app) as client:
        assert client.get('/api/health').status_code == 200
        assert client.post('/api/events', json={'timestamp': -1}).status_code == 422
        assert client.post('/api/replay/start', json={'scenario': 'invalid'}).status_code == 422
        assert client.post('/api/replay/pcap', content=b'invalid').status_code == 422
        assert client.post('/api/replay/start', json={'scenario': 'ALL', 'speed': 10000}).status_code == 200
        # Await the actual asynchronous task instead of sleeping a fixed duration.
        client.portal.call(lambda: app.state.replay_task)
        assert client.get('/api/telemetry').json()['replay_status'] == 'complete'
        alerts = client.get('/api/alerts?limit=1000').json()
        assert set(CLASSES[1:]) <= {a['threat_class'] for a in alerts}
        root = client.get('/', follow_redirects=False)
        assert root.status_code == 307
        assert root.headers['location'] == 'http://localhost:3300'
        benchmark = client.get('/api/benchmark')
        assert benchmark.status_code == 200
        assert benchmark.json()['throughput_target'] == 2000
        assert 'excludes capture, HTTP, SSE and rendering' in benchmark.json()['scope']


def test_passive_pipeline_never_opens_network_socket(monkeypatch):
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError('Passive pipeline attempted network IO')
    monkeypatch.setattr(socket, 'socket', forbidden)
    pipeline = Pipeline()
    for label in CLASSES:
        for event in scenario(label):
            pipeline = pipeline if event.timestamp >= pipeline.extractor.watermark * 1000 else Pipeline()
            pipeline.process(event)


def test_bad_pcap_length_is_rejected(tmp_path):
    path = tmp_path / 'bad.pcap'
    path.write_bytes(struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack('!IIII', 1, 0, 20000000, 20000000))
    with pytest.raises(ValueError, match='length'):
        list(PcapReader().read_packets(path))

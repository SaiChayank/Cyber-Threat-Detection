"""Slow-HTTP exhaustion from passive TCP metadata; request contents never inspected."""
import pytest

from detection.pipeline import Pipeline
from features.slow_http import MIN_SLOW_CONNECTIONS, SlowHttpState
from ingest.metadata import from_packet
from schemas.flow_record import FlowRecord
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0
CLIENT, SERVER = '10.0.0.66', '192.0.2.80'


def tcp(offset_ms, port, size, src=CLIENT, dst=SERVER, client_side=True, **fields):
    sport, dport = (port, 80) if client_side else (80, port)
    return TrafficEvent(timestamp=START + offset_ms, src_ip=src if client_side else dst,
                        dst_ip=dst if client_side else src, src_port=sport, dst_port=dport,
                        protocol=6, bytes=size, **fields)


def trickle(connections=60, duration_s=60, interval_s=15):
    """Each connection sends a partial request, then a tiny header line every interval."""
    events = []
    for index in range(connections):
        opened = index * 100
        events.append(tcp(opened, 40000 + index, 300))
        events.extend(tcp(opened + step * interval_s * 1000, 40000 + index, 70)
                      for step in range(1, duration_s // interval_s + 1))
    return sorted(events, key=lambda e: e.timestamp)


def slow_alerts(events, pipeline=None):
    pipeline = pipeline or Pipeline()
    return [a for e in events for a in pipeline.process(e)
            if a.threat_class == 'DDOS' and a.raw_evidence_metrics.get('ddos_subtype') == 'slow_http']


def test_many_long_low_rate_connections_raise_slow_http_alert_while_streaming():
    events = trickle()
    alerts = slow_alerts(events)
    assert alerts  # The pipeline's 30-second dedup re-raises an ongoing attack.
    assert all(b.timestamp - a.timestamp >= 30000 for a, b in zip(alerts, alerts[1:]))
    alert = alerts[0]
    evidence = alert.raw_evidence_metrics
    assert evidence['slow_http_connections'] >= MIN_SLOW_CONNECTIONS
    assert evidence['slow_http_target'] == f'{SERVER}:80'
    assert evidence['slow_http_mean_client_rate_bps'] < 100
    assert alert.severity == 'CRITICAL' and alert.src_ip == CLIENT
    assert alert.timestamp < events[-1].timestamp  # Raised before the capture ends.
    assert 'request contents not inspected' in alert.supporting_evidence


def test_browser_sized_or_busy_connections_do_not_alert():
    browser = trickle(connections=6)
    assert slow_alerts(browser) == []
    busy = sorted((tcp(index * 100 + step * 1000, 40000 + index, 1500)
                   for index in range(60) for step in range(60)), key=lambda e: e.timestamp)
    assert slow_alerts(busy) == []  # Many long connections, but not low-rate.


def test_short_closed_connections_do_not_accumulate():
    events = []
    for index in range(200):
        start = index * 300
        events += [tcp(start, 40000 + index, 400),
                   tcp(start + 100, 40000 + index, 52, client_side=False),
                   tcp(start + 200, 40000 + index, 52, tcp_fin_rst=True)]
    state = SlowHttpState()
    for event in events:
        features = state.update(event)
    assert features['slow_http_open_connections'] == 0
    assert slow_alerts(events) == []


def test_server_reset_closes_the_client_connection():
    state = SlowHttpState()
    state.update(tcp(0, 40000, 300))
    state.update(tcp(10, 40001, 300))
    features = state.update(tcp(20, 40000, 40, client_side=False, tcp_fin_rst=True))
    assert features['slow_http_open_connections'] == 1


def test_idle_connections_expire_and_handshakes_create_no_state():
    state = SlowHttpState()
    for index in range(10):
        state.update(tcp(index, 40000 + index, 300))
    assert state.update(tcp(121_000, 41000, 300))['slow_http_open_connections'] == 1
    syn_only = SlowHttpState()
    syn_only.update(tcp(0, 40000, 60, syn=True, syn_packets=1))
    syn_only.update(tcp(1, 40000, 52, client_side=False))
    assert not syn_only.pairs


def test_failed_persistence_leaves_slow_http_state_unchanged():
    pipeline = Pipeline()
    for event in trickle(connections=5, duration_s=15):
        pipeline.process(event)
    before = {key: dict(pair.active) for key, pair in pipeline.extractor.slow_http.pairs.items()}

    def fail(alerts):
        raise OSError('disk full')
    with pytest.raises(OSError):
        pipeline.process(tcp(20_000, 49999, 300), persist=fail)
    after = {key: dict(pair.active) for key, pair in pipeline.extractor.slow_http.pairs.items()}
    assert after == before


@pytest.mark.parametrize('flags, expected', [(0x18, None), (0x11, True), (0x04, True), (0x02, None)])
def test_packet_fin_or_rst_is_carried_and_omitted_otherwise(flags, expected):
    flow = FlowRecord(flow_id='f', src_ip=CLIENT, dst_ip=SERVER, src_port=40000, dst_port=80, protocol=6,
                      timestamp_start=START, timestamp_end=START, packets_forward=1, packets_backward=0,
                      bytes_forward=60, bytes_backward=0, tcp_flags_forward=flags, is_unidirectional=True)
    event = from_packet(flow)
    assert event.tcp_fin_rst is expected
    assert ('tcp_fin_rst' in event.model_dump()) is (expected is not None)

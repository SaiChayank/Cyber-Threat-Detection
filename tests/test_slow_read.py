"""Slow-read exhaustion from the client's advertised TCP window; contents never inspected."""
import socket
import struct

import pytest

from detection.pipeline import Pipeline
from features.slow_read import MIN_SLOW_READ_CONNECTIONS, SlowReadState
from ingest.metadata import from_packet
from ingest.protocol_parsers import ProtocolParser
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0
CLIENT, SERVER = '10.0.0.77', '192.0.2.90'


def ack(offset_ms, port, window, client_side=True, **fields):
    sport, dport = (port, 80) if client_side else (80, port)
    return TrafficEvent(timestamp=START + offset_ms, src_ip=CLIENT if client_side else SERVER,
                        dst_ip=SERVER if client_side else CLIENT, src_port=sport, dst_port=dport,
                        protocol=6, bytes=52, tcp_window=window, **fields)


def stalled_readers(connections=60, duration_s=60, interval_s=10, window=0):
    events = [ack(i * 50 + step * interval_s * 1000, 40000 + i, window)
              for i in range(connections) for step in range(duration_s // interval_s + 1)]
    return sorted(events, key=lambda e: e.timestamp)


def slow_read_alerts(events):
    pipeline = Pipeline()
    return [a for e in events for a in pipeline.process(e)
            if a.threat_class == 'DDOS' and a.raw_evidence_metrics.get('ddos_subtype') == 'slow_read']


def test_many_long_tiny_window_connections_raise_slow_read_alert():
    events = stalled_readers()
    alerts = slow_read_alerts(events)
    assert alerts and alerts[0].timestamp < events[-1].timestamp
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['slow_read_connections'] >= MIN_SLOW_READ_CONNECTIONS
    assert evidence['slow_read_mean_window'] <= 256 and evidence['slow_read_target'] == f'{SERVER}:80'
    assert 'tiny advertised receive window' in alerts[0].supporting_evidence


def test_normal_windows_few_connections_and_reopened_windows_do_not_alert():
    assert slow_read_alerts([ack(e.timestamp - START, e.src_port, 65535) for e in stalled_readers()]) == []
    assert slow_read_alerts(stalled_readers(connections=6)) == []
    reopened = []
    for e in stalled_readers():
        reopened.append(e)
        reopened.append(ack(e.timestamp - START + 5000, e.src_port, 29200))
    assert slow_read_alerts(sorted(reopened, key=lambda e: e.timestamp)) == []


def test_syn_packets_and_server_side_events_create_no_state():
    state = SlowReadState()
    state.update(ack(0, 40000, 0, syn=True))
    state.update(ack(1, 40000, 0, client_side=False))
    state.update(TrafficEvent(timestamp=START, src_ip=CLIENT, dst_ip=SERVER, src_port=40000, dst_port=80))
    assert not state.pairs


def test_fin_rst_and_idle_close_connections():
    state = SlowReadState()
    for port in range(40000, 40010):
        state.update(ack(port - 40000, port, 0))
    closed = state.update(ack(20, 40000, 0, tcp_fin_rst=True))
    assert closed['slow_read_open_connections'] == 9
    assert state.update(ack(130_000, 41000, 0))['slow_read_open_connections'] == 1


def test_failed_persistence_leaves_slow_read_state_unchanged():
    pipeline = Pipeline()
    for event in stalled_readers(connections=5, duration_s=10):
        pipeline.process(event)
    before = dict(pipeline.extractor.slow_read.pairs.items())

    def fail(alerts):
        raise OSError('disk full')
    with pytest.raises(OSError):
        pipeline.process(ack(30_000, 49999, 0), persist=fail)
    assert dict(pipeline.extractor.slow_read.pairs.items()) == before


def test_window_is_parsed_from_packets_and_omitted_when_absent():
    tcp = struct.pack('!HHIIHHHH', 40000, 80, 1, 1, (5 << 12) | 0x10, 0x00C8, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(CLIENT), socket.inet_aton(SERVER))
    flow, dns, tls = ProtocolParser().parse_packet(b'\x00' * 12 + b'\x08\x00' + ip + tcp, 1_700_000_000.0)
    assert flow.tcp_window_forward == 200
    assert from_packet(flow).tcp_window == 200
    assert 'tcp_window' not in TrafficEvent(timestamp=1, src_ip=CLIENT, dst_ip=SERVER).model_dump()

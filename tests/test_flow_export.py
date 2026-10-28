"""NetFlow v5/v9, IPFIX and sFlow v5 import from received export datagrams; passive only."""
import json
import socket
import struct

import pytest
from fastapi.testclient import TestClient

from backend.application import app
from datasets import evaluate_lab
from datasets.lab_labels import FORMAT, LabelError, load
from detection.pipeline import Pipeline
from ingest.flow_export import FlowExportDecoder, read_flow_export
from replay.cli import metadata

EXPORT_S = 1_700_000_100
UPTIME_MS = 500_000
BOOT_MS = EXPORT_S * 1000 - UPTIME_MS


def ip(text):
    return socket.inet_aton(text)


def ethernet_ipv4(src, dst, proto, l4, total=None):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total or 20 + len(l4), 1, 0, 64, proto, 0, ip(src), ip(dst))
    return b'\x00' * 12 + b'\x08\x00' + header + l4


def udp_frame(payload, src='192.0.2.1', dst='10.9.9.9', sport=40000, dport=2055):
    return ethernet_ipv4(src, dst, 17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload)


def pcap(frames):
    out = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ms, frame in frames:
        out += struct.pack('<IIII', int(ms // 1000), int(ms % 1000) * 1000, len(frame), len(frame)) + frame
    return out


def v5_record(src, dst, sport, dport, proto, packets, octets, flags, last_ms):
    return (ip(src) + ip(dst) + ip('0.0.0.0') + struct.pack('!HHIIII', 1, 2, packets, octets, last_ms - 1000, last_ms)
            + struct.pack('!HHBBBBHHBBH', sport, dport, 0, flags, proto, 0, 0, 0, 24, 24, 0))


def netflow5(records):
    return struct.pack('!HHIIIIBBH', 5, len(records), UPTIME_MS, EXPORT_S, 0, 1, 0, 0, 0) + b''.join(records)


V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (2, 4), (1, 4), (21, 4), (22, 4)]


def v9_data(src, dst, sport, dport, proto, flags, packets, octets, last_ms):
    return (ip(src) + ip(dst) + struct.pack('!HHBBIIII', sport, dport, proto, flags, packets, octets, last_ms, last_ms - 500))


def netflow9(flowsets, source_id=7):
    return struct.pack('!HHIIII', 9, 0, UPTIME_MS, EXPORT_S, 1, source_id) + b''.join(flowsets)


def flowset(set_id, body, pad_to=4):
    body += b'\x00' * (-(len(body) + 4) % pad_to)
    return struct.pack('!HH', set_id, 4 + len(body)) + body


def v9_template(template_id=256, fields=V9_FIELDS):
    return flowset(0, struct.pack('!HH', template_id, len(fields)) + b''.join(struct.pack('!HH', *f) for f in fields))


def ipfix(sets, domain=3):
    body = b''.join(sets)
    return struct.pack('!HHIII', 10, 16 + len(body), EXPORT_S, 1, domain) + body


IPFIX_TEMPLATE = (struct.pack('!HH', 300, 11)
                  + b''.join(struct.pack('!HH', i, n) for i, n in [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 2), (2, 8), (1, 8), (153, 8)])
                  + struct.pack('!HHI', 0x8000 | 1, 8, 29305)     # reverse octetDeltaCount (RFC 5103)
                  + struct.pack('!HH', 82, 0xFFFF))                # interfaceName, variable length


def ipfix_record(end_ms, reverse, name=b'eth0'):
    return (ip('10.0.0.8') + ip('203.0.113.9') + struct.pack('!HHBH', 51000, 443, 6, 0x18)
            + struct.pack('!QQQQ', 40, 52000, end_ms, reverse) + bytes([len(name)]) + name)


def sflow(samples):
    head = struct.pack('!II', 5, 1) + ip('192.0.2.50') + struct.pack('!IIII', 0, 1, 1000, len(samples))
    return head + b''.join(struct.pack('!II', fmt, len(body)) + body for fmt, body in samples)


def sflow_flow_sample(rate, headers):
    records = b''
    for frame_length, header in headers:
        padded = header + b'\x00' * (-len(header) % 4)
        body = struct.pack('!IIII', 1, frame_length, 4, len(header)) + padded
        records += struct.pack('!II', 1, len(body)) + body
    return struct.pack('!IIIIIIII', 1, 3, rate, rate * 10, 0, 1, 2, len(headers)) + records


def test_netflow_v5_records_become_end_time_events_with_flag_semantics():
    decoder = FlowExportDecoder()
    events = decoder.decode(netflow5([
        v5_record('10.0.0.1', '192.0.2.10', 51000, 80, 6, 3000, 120000, 0x02, 400_000),
        v5_record('10.0.0.2', '203.0.113.5', 52000, 443, 6, 20, 9000, 0x1B, 399_000),
        v5_record('10.0.0.3', '198.51.100.7', 53000, 53, 17, 1, 70, 0, 401_000)]), '192.0.2.1', 0)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    syn, web, dns = sorted(events, key=lambda e: str(e.src_ip))
    assert syn.timestamp == BOOT_MS + 400_000 and (syn.packets, syn.bytes) == (3000, 120000)
    assert syn.syn and syn.syn_packets == 3000 and syn.tcp_fin_rst is None
    assert web.syn and web.syn_packets is None and web.tcp_fin_rst is True and web.encrypted
    assert dns.protocol == 17 and dns.syn_packets is None and not dns.reverse_observed
    assert decoder.stats['records'] == 3


def test_netflow_v9_needs_its_template_and_ignores_padding():
    decoder = FlowExportDecoder()
    data = flowset(256, v9_data('10.0.0.4', '192.0.2.20', 40000, 22, 6, 0x12, 4, 300, 450_000)
                   + v9_data('10.0.0.5', '192.0.2.21', 40001, 23, 6, 0x10, 9, 900, 449_000), pad_to=8)
    assert decoder.decode(netflow9([data]), '192.0.2.1', 0) == []
    assert decoder.stats['missing_template'] == 1
    events = decoder.decode(netflow9([v9_template(), data]), '192.0.2.1', 0)
    assert [str(e.dst_ip) for e in events] == ['192.0.2.21', '192.0.2.20']
    assert events[1].timestamp == BOOT_MS + 450_000 and events[1].dst_port == 22
    other_exporter = decoder.decode(netflow9([data]), '192.0.2.99', 0)
    assert other_exporter == [] and decoder.stats['missing_template'] == 2


def test_ipfix_reverse_counts_variable_fields_and_template_withdrawal():
    decoder = FlowExportDecoder()
    end = EXPORT_S * 1000 - 250
    events = decoder.decode(ipfix([flowset(2, IPFIX_TEMPLATE), flowset(300, ipfix_record(end, 1100))]), '192.0.2.1', 0)
    (event,) = events
    assert (event.timestamp, event.bytes, event.packets) == (end, 52000, 40)
    assert event.reverse_observed and event.reverse_bytes == 1100 and event.encrypted
    withdraw = flowset(2, struct.pack('!HH', 300, 0))
    assert decoder.decode(ipfix([withdraw, flowset(300, ipfix_record(end, 5))]), '192.0.2.1', 0) == []
    assert decoder.stats['missing_template'] == 1


def test_sflow_samples_scale_by_rate_and_survive_truncated_headers():
    udp_header = ethernet_ipv4('198.51.100.30', '10.0.0.9', 17, struct.pack('!HHHH', 123, 40000, 1380, 0) + b'\x00' * 80,
                               total=1400)[:128]
    syn_header = ethernet_ipv4('10.0.0.66', '192.0.2.80', 6,
                               struct.pack('!HHIIHHHH', 41000, 80, 1, 0, (5 << 12) | 0x02, 1024, 0, 0))
    datagram = sflow([(2, b'\x00' * 16), (1, sflow_flow_sample(100, [(1418, udp_header), (64, syn_header)]))])
    decoder = FlowExportDecoder()
    udp, syn = sorted(decoder.decode(datagram, '192.0.2.50', 1_700_000_000_000.0), key=lambda e: e.protocol, reverse=True)
    assert (udp.packets, udp.bytes, udp.src_port, udp.dst_port) == (100, 140000, 123, 40000)
    assert syn.syn and syn.syn_packets == 100 and syn.timestamp == 1_700_000_000_000.0


@pytest.mark.parametrize('datagram, counter', [
    (netflow5([b'\x00' * 10]), 'malformed'),
    (netflow9([struct.pack('!HH', 256, 2)]), 'malformed'),
    (struct.pack('!HH', 7, 0) + b'\x00' * 20, 'unsupported'),
    (sflow([(1, b'\x00' * 3)])[:-1], 'malformed'),
])
def test_malformed_or_unknown_datagrams_are_counted_not_raised(datagram, counter):
    decoder = FlowExportDecoder()
    assert decoder.decode(datagram, '192.0.2.1', 0) == []
    assert decoder.stats[counter] == 1


def test_capture_reader_keeps_only_export_ports_and_rejects_truncation(tmp_path):
    good = netflow5([v5_record('10.0.0.1', '192.0.2.10', 51000, 80, 6, 5, 400, 0x18, 400_000)])
    path = tmp_path / 'export.pcap'
    path.write_bytes(pcap([(0, udp_frame(good)), (1, udp_frame(good, dport=5353)),
                           (2, udp_frame(good, dport=4739))]))
    decoder = FlowExportDecoder()
    assert len(list(read_flow_export(path, decoder))) == 2
    assert decoder.stats['other_packets'] == 1
    path.write_bytes(path.read_bytes()[:-3])
    with pytest.raises(ValueError, match='Truncated'):
        list(read_flow_export(path))


def syn_flood_export(tmp_path):
    records = [v5_record(f'10.1.{i // 250}.{i % 250 + 1}', '192.0.2.10', 50000 + i, 80, 6, 400, 16000, 0x02,
                         400_000 + i * 20) for i in range(25)]
    path = tmp_path / 'flood.pcap'
    path.write_bytes(pcap([(0, udp_frame(netflow5(records)))]))
    return path


def test_exported_syn_flood_flows_raise_ddos_through_offline_replay(tmp_path):
    pipeline = Pipeline()
    alerts = [a for e in metadata(syn_flood_export(tmp_path), 'flow-export') for a in pipeline.process(e)]
    assert any(a.threat_class == 'DDOS' and a.dst_ip == '192.0.2.10' for a in alerts)


def test_lab_harness_scores_flow_export_captures(tmp_path):
    syn_flood_export(tmp_path)
    labels = tmp_path / 'flood.json'
    labels.write_text(json.dumps(dict(format=FORMAT, capture='flood.pcap', source='flow_export', episodes=[
        dict(id='flood', label='DDOS', start_ms=0, end_ms=2e12, hosts=['192.0.2.10'])])))
    capture = evaluate_lab.evaluate([labels])['captures'][0]
    assert capture['source'] == 'flow_export' and capture['events'] == 25
    assert capture['ingest']['records'] == 25 and capture['episodes'][0]['detected']
    jsonl = tmp_path / 'events.jsonl'
    jsonl.write_text('')
    labels.write_text(json.dumps(dict(format=FORMAT, capture='events.jsonl', source='flow_export', episodes=[])))
    with pytest.raises(LabelError, match='flow_export needs a .pcap'):
        load(labels)


def test_upload_api_replays_flow_export_capture(tmp_path, monkeypatch):
    monkeypatch.setenv('ALERT_DB', str(tmp_path / 'export.db'))
    capture = syn_flood_export(tmp_path).read_bytes()
    with TestClient(app) as client:
        assert client.post('/api/replay/pcap?speed=10000&source=flow_export', content=capture).status_code == 200
        client.portal.call(lambda: app.state.replay_task)
        state = client.get('/api/telemetry').json()
        assert state['processed'] == 25 and state['replay_status'] == 'complete'
        assert client.post('/api/replay/pcap?source=netflow', content=capture).status_code == 422

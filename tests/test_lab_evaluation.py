import json
import struct

import pytest

from datasets import evaluate_lab
from datasets.lab_labels import FORMAT, LabelError, load
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0  # 2023-11-14T22:13:20Z


def fan_out(source, offset_ms, count=32):
    return [TrafficEvent(timestamp=START + offset_ms + index * 100, src_ip=source,
                         dst_ip='198.51.100.20', src_port=49152, dst_port=1000 + index,
                         protocol=6, packets=1, bytes=60, syn=True, syn_packets=1)
            for index in range(count)]


def quiet(source, offset_ms, count=4):
    return [TrafficEvent(timestamp=START + offset_ms + index * 2000, src_ip=source,
                         dst_ip='198.51.100.5', src_port=50000, dst_port=80, protocol=6, bytes=400)
            for index in range(count)]


def write_capture(tmp_path, events, name='capture.jsonl'):
    path = tmp_path / name
    path.write_text(''.join(event.model_dump_json() + '\n' for event in sorted(events, key=lambda e: e.timestamp)))
    return path


def write_labels(tmp_path, episodes, capture='capture.jsonl', split='test', name='labels.json'):
    path = tmp_path / name
    path.write_text(json.dumps(dict(format=FORMAT, capture=capture, split=split, episodes=episodes)))
    return path


def episode(id, label, start_ms, end_ms, hosts, scenario=None):
    entry = dict(id=id, label=label, start_ms=START + start_ms, end_ms=START + end_ms, hosts=hosts)
    return entry | ({'scenario': scenario} if scenario else {})


def test_labelled_fan_out_is_detected_and_hard_negative_counts_as_false_alert(tmp_path):
    write_capture(tmp_path, quiet('10.0.0.99', 0, 20) + fan_out('10.0.0.10', 1000)
                  + fan_out('10.0.0.50', 20000))
    labels = write_labels(tmp_path, [
        episode('scan', 'RECONNAISSANCE', 1000, 5000, ['10.0.0.10'], 'vertical_scan'),
        episode('inventory', 'BENIGN', 20000, 24000, ['10.0.0.50/32'], 'authorised_inventory')])
    report = evaluate_lab.evaluate([labels])
    capture = report['captures'][0]
    scan = next(e for e in capture['episodes'] if e['id'] == 'scan')
    assert scan['observed'] and scan['detected'] and scan['events'] == 32
    assert scan['first_correct_alert']['events_into_episode'] < 32  # Raised while streaming.
    assert scan['first_correct_alert']['time_to_detect_ms'] >= 0
    recon = report['summary']['all']['threats']['RECONNAISSANCE']
    assert (recon['episodes'], recon['detected_episodes'], recon['episode_recall']) == (1, 1, 1.0)
    assert recon['false_alerts_on_benign'] >= 1
    assert recon['alert_precision'] < 1
    benign = report['summary']['all']['benign']
    assert benign['labelled_episodes_with_alerts'] == 1
    assert benign['events'] == capture['background']['events'] + 32
    assert set(report['summary']) == {'all', 'test'}


def test_low_rate_events_labelled_as_flood_are_reported_missed(tmp_path):
    write_capture(tmp_path, quiet('10.0.0.7', 0, 6))
    labels = write_labels(tmp_path, [
        episode('flood', 'DDOS', 0, 12000, ['198.51.100.5'], 'udp_flood')])
    ddos = evaluate_lab.evaluate([labels])['summary']['all']['threats']['DDOS']
    assert (ddos['episodes'], ddos['detected_episodes'], ddos['episode_recall']) == (1, 0, 0.0)
    assert ddos['median_time_to_detect_ms'] is None


def test_overlapping_episodes_are_counted_as_ambiguous(tmp_path):
    write_capture(tmp_path, quiet('10.0.0.7', 0, 3))
    labels = write_labels(tmp_path, [episode('a', 'BENIGN', 0, 10000, []),
                                     episode('b', 'BOTNET_C2', 0, 10000, ['10.0.0.7'])])
    report = evaluate_lab.evaluate([labels])
    assert report['captures'][0]['ambiguous_events'] == 3
    assert report['captures'][0]['episodes'][0]['events'] == 3  # First listed episode wins.


def test_splits_are_summarised_separately(tmp_path):
    write_capture(tmp_path, fan_out('10.0.0.10', 0), 'train.jsonl')
    write_capture(tmp_path, quiet('10.0.0.7', 0), 'test.jsonl')
    train = write_labels(tmp_path, [episode('s', 'RECONNAISSANCE', 0, 4000, ['10.0.0.10'])],
                         'train.jsonl', 'train', 'train.json')
    test = write_labels(tmp_path, [], 'test.jsonl', 'test', 'test.json')
    summary = evaluate_lab.evaluate([train, test])['summary']
    assert set(summary) == {'all', 'train', 'test'}
    assert summary['train']['threats']['RECONNAISSANCE']['episodes'] == 1
    assert summary['test']['threats']['RECONNAISSANCE']['episodes'] == 0
    assert summary['all']['events'] == 36


def test_pcap_capture_is_read_through_runtime_ingest(tmp_path):
    header = struct.pack('!IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    tcp = struct.pack('!HHIIHHHH', 50000, 80, 1, 0, (5 << 12) | 0x10, 65535, 0, 0)
    packet = ethernet + ip + tcp
    (tmp_path / 'lab.pcap').write_bytes(header + b''.join(
        struct.pack('!IIII', 1700000000 + i, 0, len(packet), len(packet)) + packet for i in range(3)))
    labels = write_labels(tmp_path, [dict(id='web', label='BENIGN', start='2023-11-14T22:13:20Z',
                                          end='2023-11-14T22:13:21Z', hosts=['10.0.0.0/24'])], 'lab.pcap')
    capture = evaluate_lab.evaluate([labels])['captures'][0]
    assert capture['events'] == 3
    assert capture['episodes'][0]['events'] == 2 and capture['background']['events'] == 1
    assert capture['ingest']['truncated_packets'] == 0
    assert capture['ingest']['total_corrupt_packets'] == 0


def test_cli_writes_report_and_never_modifies_inputs(tmp_path, capsys):
    capture = write_capture(tmp_path, fan_out('10.0.0.10', 0))
    labels = write_labels(tmp_path, [episode('s', 'RECONNAISSANCE', 0, 4000, ['10.0.0.10'])])
    before = {path: path.read_bytes() for path in (capture, labels)}
    out = tmp_path / 'report.json'
    assert evaluate_lab.main([str(labels), '--out', str(out)]) == 0
    report = json.loads(out.read_text())
    assert report['format'] == 'ps26145-lab-evaluation/1'
    assert report['captures'][0]['capture_sha256'] == evaluate_lab.sha256(capture)
    assert report['pipeline']['dns_tunnel_candidate'] is False
    assert 'RECONNAISSANCE' in capsys.readouterr().out
    with pytest.raises(SystemExit) as refused:
        evaluate_lab.main([str(labels), '--out', str(capture)])
    assert refused.value.code == 2
    assert {path: path.read_bytes() for path in before} == before


def test_invalid_jsonl_event_reports_line(tmp_path):
    (tmp_path / 'capture.jsonl').write_text('{"timestamp": -1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}\n')
    labels = write_labels(tmp_path, [])
    with pytest.raises(ValueError, match='capture.jsonl:1'):
        evaluate_lab.evaluate([labels])


@pytest.mark.parametrize('change, message', [
    (dict(format='other'), 'format'),
    (dict(capture='missing.jsonl'), 'not found'),
    (dict(capture='notes.txt'), 'capture must be'),
    (dict(split='holdout'), 'split'),
    (dict(episodes={}), 'episodes must be a list'),
    (dict(episodes=[dict(id='x', label='WORM', start_ms=0, end_ms=1)]), 'label must be'),
    (dict(episodes=[dict(id='x', label='DDOS', start_ms=5, end_ms=1)]), 'end precedes start'),
    (dict(episodes=[dict(id='x', label='DDOS', start='2023-11-14T22:13:20', end_ms=1)]), 'UTC offset'),
    (dict(episodes=[dict(id='x', label='DDOS', start_ms=0, end_ms=1, hosts=['10.0.0.300'])]), 'invalid host'),
    (dict(episodes=[dict(id='x', label='DDOS', start_ms=0, end_ms=1)] * 2), 'unique'),
    (dict(episodes=[dict(label='DDOS', start_ms=0, end_ms=1)]), 'missing id'),
])
def test_label_file_validation(tmp_path, change, message):
    write_capture(tmp_path, quiet('10.0.0.7', 0, 1))
    (tmp_path / 'notes.txt').write_text('x')
    path = tmp_path / 'labels.json'
    path.write_text(json.dumps(dict(format=FORMAT, capture='capture.jsonl', episodes=[]) | change))
    with pytest.raises(LabelError, match=message):
        load(path)

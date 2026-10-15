import json
import struct
from decimal import Decimal

import pytest

from datasets.qualify_tqh_tls import label_errors, qualify, same_json_number, unique_uids
from ingest.protocol_parsers import ProtocolParser
from tests.test_tls_capture_qualification import frame, header


def test_source_json_round_trip_uses_exact_binary64_equality_without_tolerance():
    assert same_json_number(Decimal('31.070755004882812'), Decimal('31.070755004882813'))
    assert not same_json_number(Decimal('31.070755004882812'), Decimal('31.0707550048829'))
    assert same_json_number(Decimal('1784790811.785797'), Decimal('1784790811.7857971'))
    assert not same_json_number(Decimal('1784790811.785797'), Decimal('1784790811.7857975'))
    assert not same_json_number('NaN', 'NaN')
    assert same_json_number(None, None)
    assert not same_json_number(None, 0)


def test_duplicate_source_uid_rejected():
    with pytest.raises(ValueError, match='Duplicate'):
        unique_uids([{'uid': 'same'}, {'uid': 'same'}])


def cohort(tmp_path):
    capture = tmp_path / 'cell.pcap'
    benign = frame(1)
    malicious = benign[:30] + b'\xc0\x00\x02\x02' + benign[34:]
    capture.write_bytes(header(1) + struct.pack('<IIII', 1700000000, 100,
        len(malicious), len(malicious)) + malicious + struct.pack('<IIII', 1700000001, 100,
        len(benign), len(benign)) + benign)
    manifest = {'capture_id': 'development-fixture',
                'start_utc': '2023-11-14T22:13:19Z', 'end_utc': '2023-11-14T22:13:25Z',
                'topology': {'victims': ['192.0.2.1'], 'c2': ['192.0.2.2'],
                             'benign_gen': [], 'internal_prefix': '192.0.2.'}}
    labels, conns, ssl = [], [], []
    for number, (packet, intent) in enumerate([(malicious, 'malicious_c2'), (benign, 'benign')]):
        flow, _, tls = ProtocolParser().parse_packet(packet, 1700000000 + number)
        label = {'uid': str(number), 'orig_h': flow.src_ip, 'resp_h': flow.dst_ip,
                 'orig_p': flow.src_port, 'resp_p': flow.dst_port, 'proto': 'tcp',
                 'ts': 1700000000 + number, 'duration': 2,
                 'label': intent, 'capture_id': manifest['capture_id']}
        labels.append(label)
        conns.append({'uid': label['uid'], 'id.orig_h': flow.src_ip, 'id.resp_h': flow.dst_ip,
                      'id.orig_p': flow.src_port, 'id.resp_p': flow.dst_port,
                      'proto': 'tcp', 'ts': label['ts'], 'duration': 2})
        ssl.append({'uid': label['uid'], 'ja3': tls.ja3_hash})
    for name, value in [('manifest.json', manifest), ('gate.json', {'mode': 'partial', 'checks': {
                         'H3_balance': {'pass': False}}})]:
        (tmp_path / name).write_text(json.dumps(value))
    for name, values in [('conn.log', conns), ('labeled.jsonl', labels), ('ssl.log', ssl)]:
        (tmp_path / name).write_text('\n'.join(json.dumps(value) for value in values))
    return capture, labels, conns, manifest


def test_original_runtime_hello_joins_exact_source_uid_tuple_and_utc_window(tmp_path):
    capture, _, _, _ = cohort(tmp_path)
    result = qualify(capture, tmp_path)
    assert result['qualified']
    assert result['qualified_session_counts'] == {'malicious_c2': 1, 'benign': 1}
    assert result['qualified_sessions'][0]['packet_index'] == 1
    assert result['qualified_sessions'][0]['timestamp_ns'] == 1700000000000100000
    assert result['publisher_failed_checks'] == {'H3_balance': {'pass': False}}
    assert result['encrypted_model_training_status'] == 'BLOCKED'
    assert not result['training_performed'] and not result['prediction_performed']


def test_exact_duplicate_packet_recorded_without_dropping_raw_observation(tmp_path):
    capture, _, _, _ = cohort(tmp_path)
    data = capture.read_bytes()
    first_size = struct.unpack_from('<I', data, 32)[0]
    first_record = data[24:40 + first_size]
    capture.write_bytes(data[:40 + first_size] + first_record + data[40 + first_size:])
    result = qualify(capture, tmp_path)
    assert result['qualified']
    assert result['packet_counts']['packets'] == 3
    assert result['packet_counts']['exact_frame_timestamp_duplicates'] == 1
    assert result['packet_counts']['additional_hello_observations_same_uid'] == 1
    assert [row['packet_index'] for row in result['clienthello_observations']] == [1, 2, 3]
    assert result['qualified_session_counts'] == {'malicious_c2': 1, 'benign': 1}


def test_contradictory_session_intent_or_changed_tuple_cannot_pass(tmp_path):
    _, labels, conns, manifest = cohort(tmp_path)
    bad = dict(labels[1], label='malicious_c2')
    assert 'C2 label contradicts publisher topology' in label_errors(bad, conns[1], manifest)
    bad = dict(labels[0], orig_p=50001)
    assert 'label/connection tuple or time disagrees' in label_errors(bad, conns[0], manifest)


def test_ambiguous_uid_windows_do_not_create_extra_verified_sessions(tmp_path):
    capture, labels, conns, _ = cohort(tmp_path)
    duplicate = dict(labels[0], uid='ambiguous')
    (tmp_path / 'labeled.jsonl').write_text('\n'.join(json.dumps(r) for r in labels + [duplicate]))
    duplicate = dict(conns[0], uid='ambiguous')
    (tmp_path / 'conn.log').write_text('\n'.join(json.dumps(r) for r in conns + [duplicate]))
    result = qualify(capture, tmp_path)
    assert not result['qualified']
    assert 'malicious_c2' not in result['qualified_session_counts']
    assert result['packet_counts']['unmatched_or_ambiguous_clienthellos'] == 1


def test_null_and_missing_duration_do_not_become_observed_zero(tmp_path):
    _, labels, conns, manifest = cohort(tmp_path)
    label = dict(labels[0], duration=None)
    conn = dict(conns[0])
    del conn['duration']
    assert not label_errors(label, conn, manifest)
    conn['duration'] = 0
    assert 'label/connection tuple or time disagrees' in label_errors(label, conn, manifest)

"""Qualification counts preserve original timing and do not infer DNS labels."""
import importlib.util
import json
from pathlib import Path
import struct

import pytest

from tests.test_dns_visibility_audit import _packet

MODULE = Path(__file__).resolve().parents[1] / "docs/verification/burgos-benign-verification-20261021/inspect_visibility.py"
spec = importlib.util.spec_from_file_location("burgos_dns_visibility", MODULE)
visibility = importlib.util.module_from_spec(spec)
spec.loader.exec_module(visibility)


def question(kind=1, response=False):
    return struct.pack("!HHHHHH", 7, 0x8180 if response else 0x100, 1, 0, 0, 0) + b"\x04host\x04test\x00" + struct.pack("!HH", kind, 1)


def capture(tmp_path, packets, nano=False):
    body = bytes.fromhex("4d3cb2a1" if nano else "d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    for seconds, fraction, frame in packets:
        body += struct.pack("<IIII", seconds, fraction, len(frame), len(frame)) + frame
    path = tmp_path / "fixture.pcap"
    path.write_bytes(body)
    return path


def test_counts_qtypes_separate_services_and_preserve_backwards_steps(tmp_path):
    first = _packet(53, question(1))
    path = capture(tmp_path, [(20, 500000, first), (19, 0, first),
        (21, 0, _packet(53, question(16))), (22, 0, _packet(53, question(response=True))),
        (23, 0, _packet(5353, question())), (24, 0, _packet(5355, question())),
        (25, 0, _packet(53, b"short"))])
    result = visibility.inspect(path)
    assert result["counts"]["frames"] == 7
    assert result["counts"]["backwards_timestamp_steps"] == 1
    assert result["counts"]["repeated_frame_bytes"] == 1
    assert result["observed_client_qtypes"] == {"1": 2, "16": 1}
    assert result["counts"]["runtime_client_question_sidecars"] == 3
    assert result["counts"]["runtime_question_mismatches"] == 0
    assert result["counts"]["dns_responses"] == 1
    assert result["counts"]["dns_wire_incomplete_or_unparseable"] == 1
    assert result["services"] == {"udp/53": 5, "udp/5353": 1, "udp/5355": 1}
    assert result["observed_span_seconds"] == 6
    assert result["first_timestamp_utc"].endswith("20.500000+00:00")
    assert result["unique_question_sources"] == 1
    assert result["role"] is None and result["certified_independent_dns_sessions"] is None
    assert result["certified_benign_categories"] == [] and result["detector_called"] is False
    assert "host.test" not in json.dumps(result) and "192.0.2.1" not in json.dumps(result)


def test_nanosecond_encoding_does_not_become_microsecond_time(tmp_path):
    path = capture(tmp_path, [(1, 500000000, _packet(53, question())),
        (2, 0, _packet(53, question()))], nano=True)
    result = visibility.inspect(path)
    assert result["timestamp_encoding"] == "nanoseconds"
    assert result["first_timestamp_utc"].endswith("01.500000+00:00")
    assert result["observed_span_seconds"] == 0.5


@pytest.mark.parametrize("tail", [b"x", struct.pack("<IIII", 1, 0, 10, 10) + b"x",
    struct.pack("<IIII", 1, 0, 10, 9) + b"x" * 10,
    struct.pack("<IIII", 1, 1000000, 1, 1) + b"x"])
def test_truncated_or_invalid_record_fails_closed(tmp_path, tail):
    path = capture(tmp_path, [])
    path.write_bytes(path.read_bytes() + tail)
    with pytest.raises(ValueError):
        visibility.inspect(path)


def test_missing_runtime_question_is_reported_instead_of_dropped(tmp_path, monkeypatch):
    path = capture(tmp_path, [(1, 0, _packet(53, question()))])
    monkeypatch.setattr(visibility.ProtocolParser, "parse_packet", lambda *args: (None, None, None))
    result = visibility.inspect(path)
    assert result["counts"]["complete_client_question_messages"] == 1
    assert result["counts"]["wire_complete_runtime_missing"] == 1
    assert result["counts"].get("runtime_client_question_sidecars", 0) == 0


def test_no_dns_does_not_fabricate_sessions_or_question_types(tmp_path):
    path = capture(tmp_path, [(1, 0, _packet(8125, b"opaque"))])
    result = visibility.inspect(path)
    assert result["observed_client_qtypes"] == {} and result["unique_question_sources"] == 0
    assert result["certified_independent_dns_sessions"] is None
    assert result["complete_question_name_length_max"] is None

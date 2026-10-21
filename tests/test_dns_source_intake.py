"""Selected public capture intake must verify identity before opening a header."""
import hashlib
import importlib.util
from pathlib import Path
import struct

import pytest

MODULE = Path(__file__).resolve().parents[1] / "docs/verification/dns-public-session-screen-20261021/acquire_selected_metadata.py"
spec = importlib.util.spec_from_file_location("dns_source_intake", MODULE)
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)


class Response:
    status_code = 200
    headers = {"content-type": "application/octet-stream"}

    def __init__(self, blocks):
        self.blocks = blocks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_bytes(self, chunk_size):
        assert chunk_size == 65536
        yield from self.blocks


class Client:
    def __init__(self, blocks):
        self.blocks = blocks

    def stream(self, method, url, headers):
        assert method == "GET" and url == intake.AC_URL
        assert headers == {"Accept-Encoding": "identity"}
        return Response(self.blocks)


def header(linktype=1):
    return bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, linktype)


def test_verified_capture_reads_only_global_header_and_assigns_no_evaluation_role(tmp_path, monkeypatch):
    raw = header() + b"opaque test bytes; never a query or packet fixture"
    monkeypatch.setattr(intake, "ROOT", tmp_path)
    monkeypatch.setattr(intake, "AC_HASH", hashlib.sha256(raw).hexdigest())
    observed = []
    original = intake.validate_header

    def validate(value):
        observed.append(value)
        return original(value)

    monkeypatch.setattr(intake, "validate_header", validate)
    result = intake.acquire_ac(Client([raw[:17], raw[17:]]))
    assert observed == [header()]
    assert result["linktype"] == 1 and result["snaplen"] == 262144
    assert result["header_bytes_read"] == 24
    assert result["role"] is None and result["packet_records_parsed"] == 0
    assert result["candidate_scored"] is False
    assert (tmp_path / result["artifact"]).read_bytes() == raw


def test_wrong_hash_is_rejected_before_capture_header_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(intake, "ROOT", tmp_path)

    def forbidden(_):
        raise AssertionError("Never validate unverified bytes")

    monkeypatch.setattr(intake, "validate_header", forbidden)
    result = intake.acquire_ac(Client([header()]))
    assert result["qualification"] == "REJECT_HASH_MISMATCH_HEADER_NOT_OPENED"
    assert result["header_bytes_read"] == 0 and result["role"] is None


def test_oversized_download_stops_before_header_inspection(tmp_path, monkeypatch):
    monkeypatch.setattr(intake, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="download bound"):
        intake.acquire_ac(Client([b"x" * 65536] * 49))
    path = tmp_path / "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap"
    assert path.stat().st_size == 3 * 1024 * 1024


@pytest.mark.parametrize("raw", [header(linktype=113), b"incomplete"])
def test_unsupported_or_truncated_native_capture_is_not_converted(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(intake, "ROOT", tmp_path)
    monkeypatch.setattr(intake, "AC_HASH", hashlib.sha256(raw).hexdigest())
    result = intake.acquire_ac(Client([raw]))
    assert result["qualification"] == "UNSUPPORTED_NATIVE_HEADER"
    assert result["packet_records_parsed"] == 0 and result["role"] is None
    assert (tmp_path / result["artifact"]).read_bytes() == raw


def test_existing_intake_is_never_overwritten(tmp_path, monkeypatch):
    monkeypatch.setattr(intake, "ROOT", tmp_path)
    path = tmp_path / "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"preserved intake")
    with pytest.raises(FileExistsError):
        intake.acquire_ac(Client([header()]))
    assert path.read_bytes() == b"preserved intake"

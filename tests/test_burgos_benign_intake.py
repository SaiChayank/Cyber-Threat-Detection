"""Bounded selected-member acquisition must refuse changed or unsafe sources."""
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import struct
import zipfile
import zlib

import pytest

MODULE = Path(__file__).resolve().parents[1] / "docs/verification/burgos-benign-verification-20261021/acquire_member.py"
spec = importlib.util.spec_from_file_location("burgos_member_intake", MODULE)
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)


def fixture(linktype=1):
    payload = bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, linktype) + b"opaque unit bytes" * 100
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("benign_first_cap.pcap", payload)
        archive.writestr("benign_second_cap.pcap", b"do not acquire")
        archive.writestr("malicious_DoS_cap.pcap", b"do not acquire")
    raw = buffer.getvalue()
    end = struct.unpack("<4s4H2LH", raw[-22:])
    offset, size = end[6], end[5]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo("benign_first_cap.pcap")
    selection = dict(url="https://example.test/fixed.zip", archive_bytes=len(raw),
        last_modified="Fri, 07 Nov 2025 12:30:49 GMT", directory_offset=offset,
        directory_bytes=size, directory_sha256=hashlib.sha256(raw[offset:offset + size]).hexdigest(),
        member_count=3, member=info.filename, compressed_bytes=info.compress_size,
        original_bytes=info.file_size, crc32=f"{info.CRC:08x}")
    return raw, payload, selection


class Response:
    def __init__(self, data, headers, status):
        self.data = data
        self.headers = headers
        self.status_code = status
        self.body_read = False

    def __enter__(self): return self
    def __exit__(self, *args): return False

    def iter_bytes(self):
        self.body_read = True
        yield self.data


class Client:
    def __init__(self, raw, selection, mode=None):
        self.raw, self.selection, self.mode = raw, selection, mode
        self.requests, self.responses = [], []

    def stream(self, method, url, headers):
        assert method == "GET" and url == self.selection["url"]
        assert headers["If-Unmodified-Since"] == self.selection["last_modified"]
        assert headers["Accept-Encoding"] == "identity"
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", headers["Range"])
        assert match
        start, end = map(int, match.groups())
        assert end - start + 1 <= 1048576
        self.requests.append((start, end))
        body = self.raw[start:end + 1]
        values = {"content-range": f"bytes {start}-{end}/{len(self.raw)}",
                  "last-modified": self.selection["last_modified"]}
        status = 206
        if self.mode == "full": status = 200
        if self.mode == "range": values["content-range"] = "bytes 0-0/1"
        if self.mode == "identity": values["last-modified"] = "changed"
        if self.mode == "encoding": values["content-encoding"] = "gzip"
        if self.mode == "short": body = body[:-1]
        if self.mode == "long": body += b"!"
        response = Response(body, values, status)
        self.responses.append(response)
        return response


def test_verified_member_only_and_existing_header_validator(tmp_path):
    raw, payload, selection = fixture()
    client = Client(raw, selection)
    target = tmp_path / "fixed.pcap"
    result = intake.acquire(client, selection, target)
    assert target.read_bytes() == payload
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["crc32"] == selection["crc32"]
    assert result["native_compatibility"] == "PASS_CLASSIC_ETHERNET_PCAP"
    assert result["header_bytes_read"] == 24 and result["packet_records_parsed"] == 0
    assert result["candidate_scored"] is False and result["role"] is None
    assert sorted(x.name for x in tmp_path.iterdir()) == ["fixed.pcap"]
    assert len(client.requests) == 4


@pytest.mark.parametrize("mode", ["full", "range", "identity", "encoding", "short", "long"])
def test_unsafe_range_response_is_rejected_before_trusting_output(tmp_path, mode):
    raw, _, selection = fixture()
    client = Client(raw, selection, mode)
    with pytest.raises(ValueError):
        intake.acquire(client, selection, tmp_path / "fixed.pcap")
    assert not list(tmp_path.iterdir())
    if mode in {"full", "range", "identity", "encoding"}:
        assert client.responses[0].body_read is False


def test_changed_directory_refuses_before_member_requests(tmp_path):
    raw, _, selection = fixture()
    selection["directory_sha256"] = "0" * 64
    client = Client(raw, selection)
    with pytest.raises(ValueError, match="directory identity"):
        intake.acquire(client, selection, tmp_path / "fixed.pcap")
    assert len(client.requests) == 1 and not list(tmp_path.iterdir())


def test_changed_compressed_bytes_never_become_a_trusted_capture(tmp_path):
    raw, _, selection = fixture()
    damaged = bytearray(raw)
    start = 30 + len(selection["member"])
    damaged[start + selection["compressed_bytes"] // 2] ^= 128
    with pytest.raises((ValueError, zlib.error)):
        intake.acquire(Client(bytes(damaged), selection), selection, tmp_path / "fixed.pcap")
    assert not (tmp_path / "fixed.pcap").exists()


def test_valid_deflate_with_bad_crc_is_rejected(tmp_path):
    raw, _, selection = fixture()
    changed = bytearray(raw)
    wrong_crc = int(selection["crc32"], 16) ^ 1
    struct.pack_into("<I", changed, 14, wrong_crc)
    struct.pack_into("<I", changed, selection["directory_offset"] + 16, wrong_crc)
    selection["crc32"] = f"{wrong_crc:08x}"
    selection["directory_sha256"] = hashlib.sha256(changed[selection["directory_offset"]:selection["directory_offset"] + selection["directory_bytes"]]).hexdigest()
    with pytest.raises(ValueError, match="CRC verification"):
        intake.acquire(Client(bytes(changed), selection), selection, tmp_path / "fixed.pcap")
    assert not (tmp_path / "fixed.pcap").exists()


def test_deflate_output_cannot_exceed_declared_size(tmp_path):
    raw, _, selection = fixture()
    changed = bytearray(raw)
    selection["original_bytes"] = 24
    struct.pack_into("<I", changed, 22, 24)
    struct.pack_into("<I", changed, selection["directory_offset"] + 24, 24)
    selection["directory_sha256"] = hashlib.sha256(changed[selection["directory_offset"]:selection["directory_offset"] + selection["directory_bytes"]]).hexdigest()
    with pytest.raises(ValueError, match="output exceeds"):
        intake.acquire(Client(bytes(changed), selection), selection, tmp_path / "fixed.pcap")
    assert not (tmp_path / "fixed.pcap").exists()


def test_local_filename_change_is_not_used_as_a_destination(tmp_path):
    raw, _, selection = fixture()
    changed = bytearray(raw)
    changed[30] ^= 1
    client = Client(bytes(changed), selection)
    with pytest.raises(ValueError, match="member name disagrees"):
        intake.acquire(client, selection, tmp_path / "fixed.pcap")
    assert len(client.requests) == 3 and not list(tmp_path.iterdir())


def test_unsupported_native_header_keeps_original_and_stops_before_packets(tmp_path):
    raw, payload, selection = fixture(linktype=113)
    target = tmp_path / "fixed.pcap"
    result = intake.acquire(Client(raw, selection), selection, target)
    assert result["native_compatibility"] == "FAIL_UNSUPPORTED_NATIVE_CAPTURE"
    assert result["stage_b_allowed"] is False and result["packet_records_parsed"] == 0
    assert target.read_bytes() == payload


@pytest.mark.parametrize("existing", ["fixed.pcap", "fixed.pcap.partial"])
def test_existing_intake_is_not_overwritten(tmp_path, existing):
    raw, _, selection = fixture()
    path = tmp_path / existing
    path.write_bytes(b"preserve")
    client = Client(raw, selection)
    with pytest.raises(FileExistsError):
        intake.acquire(client, selection, tmp_path / "fixed.pcap")
    assert path.read_bytes() == b"preserve" and client.requests == []

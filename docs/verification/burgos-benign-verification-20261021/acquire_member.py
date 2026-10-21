"""Verify exactly one pinned public ZIP member without parsing packet records."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile
import zlib

import httpx

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ingest.pcap_reader import validate_header


def acquire(client, selection, target):
    """Opaque bounded extraction; a destination becomes trusted only after CRC."""
    partial = target.with_suffix(target.suffix + ".partial")
    if target.exists() or partial.exists():
        raise FileExistsError("Preserve previously acquired or partial intake")
    ranges = []

    def fetch(start, length):
        if not (0 <= start < selection["archive_bytes"] and 0 < length <= 1048576
                and start + length <= selection["archive_bytes"]):
            raise ValueError("Range exceeds frozen bounds")
        headers = {"Range": f"bytes={start}-{start + length - 1}", "Accept-Encoding": "identity",
                   "If-Unmodified-Since": selection["last_modified"]}
        with client.stream("GET", selection["url"], headers=headers) as response:
            if response.status_code != 206:
                raise ValueError("Refuse a full-file/non-range response")
            if response.headers.get("content-range") != f"bytes {start}-{start + length - 1}/{selection['archive_bytes']}":
                raise ValueError("Unexpected Content-Range")
            if response.headers.get("last-modified") != selection["last_modified"]:
                raise ValueError("Source identity changed")
            if response.headers.get("content-encoding", "identity") != "identity":
                raise ValueError("Unexpected HTTP content encoding")
            body = bytearray()
            for block in response.iter_bytes():
                if len(body) + len(block) > length:
                    raise ValueError("Range body exceeds expected length")
                body.extend(block)
            if len(body) != length:
                raise ValueError("Short range body")
        ranges.append(dict(start=start, length=length, sha256=hashlib.sha256(body).hexdigest()))
        return bytes(body)

    directory = fetch(selection["directory_offset"], selection["directory_bytes"])
    if hashlib.sha256(directory).hexdigest() != selection["directory_sha256"]:
        raise ValueError("Published directory identity changed")
    # Standard-library ZIP directory parsing, not a new archive/capture parser.
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, selection["member_count"],
                      selection["member_count"], len(directory), 0, 0)
    with zipfile.ZipFile(io.BytesIO(directory + end)) as archive:
        matches = [item for item in archive.infolist() if item.filename == selection["member"]]
        if len(matches) != 1:
            raise ValueError("Selected member is absent or ambiguous")
        member = matches[0]
    if (member.compress_type != 8 or member.flag_bits & 1
            or member.compress_size != selection["compressed_bytes"]
            or member.file_size != selection["original_bytes"]
            or f"{member.CRC:08x}" != selection["crc32"]):
        raise ValueError("Selected member metadata changed or unsupported")
    local = struct.unpack("<4s5H3L2H", fetch(member.header_offset, 30))
    if local[0] != b"PK\x03\x04" or local[2] != member.flag_bits or local[3] != 8:
        raise ValueError("Local header disagrees with central directory")
    if not local[2] & 8 and (local[6], local[7], local[8]) != (member.CRC, member.compress_size, member.file_size):
        raise ValueError("Local integrity metadata disagrees")
    name_and_extra = fetch(member.header_offset + 30, local[9] + local[10])
    if name_and_extra[:local[9]] != selection["member"].encode("ascii"):
        raise ValueError("Local member name disagrees")
    offset = member.header_offset + 30 + local[9] + local[10]
    if offset + member.compress_size > selection["directory_offset"]:
        raise ValueError("Selected compressed stream overlaps directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    decoder = zlib.decompressobj(-15)
    count = 0
    crc = 0
    checksum = hashlib.sha256()
    compressed_checksum = hashlib.sha256()
    with partial.open("xb") as output:
        for position in range(0, member.compress_size, 1048576):
            encoded = fetch(offset + position, min(1048576, member.compress_size - position))
            compressed_checksum.update(encoded)
            decoded = decoder.decompress(encoded, member.file_size - count + 1)
            if count + len(decoded) > member.file_size or decoder.unconsumed_tail:
                raise ValueError("Inflated output exceeds declared size")
            count += len(decoded)
            crc = zlib.crc32(decoded, crc)
            checksum.update(decoded)
            output.write(decoded)
        if not decoder.eof or decoder.unused_data or count != member.file_size or crc != member.CRC:
            raise ValueError("Selected member deflate/length/CRC verification failed")
    partial.rename(target)
    with target.open("rb") as stream:
        header = stream.read(24)
    result = dict(status="MEMBER_INTEGRITY_PASS", bytes=count, crc32=f"{crc:08x}",
        sha256=checksum.hexdigest(), compressed_sha256=compressed_checksum.hexdigest(),
        header_hex=header.hex(), header_bytes_read=len(header), ranges=ranges,
        packet_records_parsed=0, candidate_scored=False, role=None,
        full_archive_checksum_verified=False)
    try:
        result["snaplen"] = validate_header(header)
        result["native_compatibility"] = "PASS_CLASSIC_ETHERNET_PCAP"
    except ValueError as error:
        result["native_compatibility"] = "FAIL_UNSUPPORTED_NATIVE_CAPTURE"
        result["header_error"] = str(error)
        result["stage_b_allowed"] = False
    return result


if __name__ == "__main__":
    plan = HERE / "selection.json"
    assert hashlib.sha256(plan.read_bytes()).hexdigest() == (HERE / "selection.sha256").read_text().strip()
    selection = json.loads(plan.read_text())
    for name, expected in selection["sources_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Frozen acquisition source changed")
    result_path = HERE / "acquisition.json"
    if result_path.exists():
        raise FileExistsError("Preserve existing acquisition evidence")
    target = ROOT / "data/raw/burgos-benign-intake-20261021/benign_first_cap.pcap"
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        result = acquire(client, selection, target)
    result["artifact"] = target.relative_to(ROOT).as_posix()
    result_path.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({key: value for key, value in result.items() if key != "ranges"}))

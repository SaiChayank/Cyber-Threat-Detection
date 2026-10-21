"""Execute the frozen bounded header/directory selection; never parse packets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import httpx

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ingest.pcap_reader import validate_header

AC_URL = "https://www.dropbox.com/scl/fi/gm9yvhhbghwviz44in1r8/dnscat2_dns_tunneling_1hr.pcap?rlkey=t2w4vejnxc695zg3d1eyzg9f6&dl=1"
AC_HASH = "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd"
BURGOS_URL = "https://riubu.ubu.es/bitstream/handle/10259/11037/Martinez-Raw_Network%20Traffic_Captures_for_IoT-Dataset_2025.zip?sequence=1&isAllowed=y"


def save(name, content):
    (HERE / name).write_bytes((json.dumps(content, indent=2) + "\n").encode())


def acquire_ac(client):
    target = ROOT / "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError("Preserve previously acquired capture")
    result = dict(source="Active Countermeasures", requested_url=AC_URL,
        expected_sha256=AC_HASH, artifact=target.relative_to(ROOT).as_posix(),
        max_bytes=3 * 1024 * 1024, header_bytes_read=0,
        packet_records_parsed=0, candidate_scored=False, role=None)
    total = 0
    checksum = hashlib.sha256()
    with client.stream("GET", AC_URL, headers={"Accept-Encoding": "identity"}) as response:
        response.raise_for_status()
        # Type/filename alone do not prove this is a capture; pin actual bytes.
        result.update(status=response.status_code, content_type=response.headers.get("content-type"))
        with target.open("xb") as output:
            for block in response.iter_bytes(chunk_size=65536):
                total += len(block)
                if total > result["max_bytes"]:
                    raise ValueError("Selected capture exceeds frozen download bound")
                checksum.update(block)
                output.write(block)
    result.update(bytes=total, sha256=checksum.hexdigest())
    if result["sha256"] != AC_HASH:
        result["qualification"] = "REJECT_HASH_MISMATCH_HEADER_NOT_OPENED"
        return result
    with target.open("rb") as stream:
        header = stream.read(24)
    result.update(header_bytes_read=len(header), header_hex=header.hex())
    try:
        result["snaplen"] = validate_header(header)
        endian = "<" if header[:4] in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")) else ">"
        result["linktype"] = struct.unpack(endian + "I", header[20:24])[0]
        result["timestamp_resolution"] = "nanoseconds" if header[:4] in (bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d")) else "microseconds"
        result["qualification"] = "SUPPORTED_NATIVE_HEADER_ONLY_SESSION_ANNOTATIONS_UNVERIFIED"
    except ValueError as error:
        result["qualification"] = "UNSUPPORTED_NATIVE_HEADER"
        result["header_error"] = str(error)
    return result


if __name__ == "__main__":
    assert hashlib.sha256((HERE / "HEADER_SELECTION.md").read_bytes()).hexdigest() == (HERE / "header-selection.sha256").read_text().strip()
    for name in ("ac-header.json", "burgos-catalogue.json"):
        if (HERE / name).exists():
            raise FileExistsError("Preserve earlier metadata acquisition result")
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        try:
            result = acquire_ac(client)
        except Exception as error:
            result = dict(source="Active Countermeasures", requested_url=AC_URL,
                qualification="ACQUISITION_UNVERIFIED", error_type=type(error).__name__,
                role=None, candidate_scored=False)
        save("ac-header.json", result)
        print(json.dumps(result), flush=True)
        module_path = ROOT / "docs/verification/udp-alternative-sources-20261019/catalogue_netslab.py"
        spec = importlib.util.spec_from_file_location("existing_zip_catalogue", module_path)
        catalogue_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(catalogue_module)
        try:
            result = catalogue_module.catalogue(client, dict(key="Martinez-Raw_Network Traffic_Captures_for_IoT-Dataset_2025.zip",
                size=1269092760, checksum="not_published_in_reviewed_metadata",
                links={"self": BURGOS_URL}))
        except Exception as error:
            result = dict(source="Burgos", url=BURGOS_URL, qualification="DIRECTORY_READ_UNVERIFIED",
                error_type=type(error).__name__, candidate_scored=False,
                note="No fallback to full archive download or member reads")
        result["reused_catalogue_source_sha256"] = hashlib.sha256(module_path.read_bytes()).hexdigest()
        save("burgos-catalogue.json", result)
        print(json.dumps(result), flush=True)

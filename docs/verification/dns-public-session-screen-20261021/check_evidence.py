"""Verify source receipts and preserved originals; no packet parsing or scoring."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / "data/raw/dns-public-session-documents-20261021"
sys.path.insert(0, str(ROOT))
from ml.dga import domain_label


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + "\n").encode())


if __name__ == "__main__":
    receipts = json.loads((HERE / "retrievals.json").read_text())
    assert len(receipts) == 9
    for record in receipts:
        path = CACHE / record["name"]
        assert record["status"] == 200 and path.stat().st_size == record["bytes"]
        assert digest(path) == record["sha256"]
    ziza = json.loads((CACHE / "ziza-record.json").read_text())
    assert ziza["id"] == "c4n7fckkz3" and ziza["version"] == 3
    description = next(item for item in ziza["files"] if item["filename"] == "dataset_description.txt")
    assert digest(CACHE / "ziza-description.txt") == description["content_details"]["sha256_hash"]
    reference = json.loads((CACHE / "netrack-ref.json").read_text())
    assert reference["object"]["sha"] == "b19ea986df5517bd8ad89efd2e16bbf302e2ac03"
    tree = json.loads((CACHE / "netrack-tree.json").read_text())
    assert tree["truncated"] is False
    by_path = {item["path"]: item for item in tree["tree"]}
    for name, remote in (("netrack-readme.txt", "README.md"), ("netrack-license.txt", "LICENSE")):
        body = (CACHE / name).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == by_path[remote]["sha"]
    ac = json.loads((HERE / "ac-header.json").read_text())
    assert ac["sha256"] == ac["expected_sha256"] == "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd"
    assert digest(ROOT / ac["artifact"]) == ac["sha256"]
    assert ac["bytes"] == 2462756 and ac["header_bytes_read"] == 24
    assert ac["linktype"] == 1 and ac["snaplen"] == 262144
    assert ac["packet_records_parsed"] == 0 and ac["candidate_scored"] is False and ac["role"] is None
    catalogue = json.loads((HERE / "burgos-catalogue.json").read_text())
    assert catalogue["conditional_identity_verified"] is True
    assert catalogue["traffic_members_decompressed"] == 0 and catalogue["packet_values_read"] is False
    assert [m["name"] for m in catalogue["members"]] == ["benign_first_cap.pcap", "benign_second_cap.pcap", "malicious_DoS_cap.pcap"]
    assert all(r["length"] <= 1048576 for r in catalogue["ranges"])
    assert catalogue["reused_catalogue_source_sha256"] == digest(ROOT / "docs/verification/udp-alternative-sources-20261019/catalogue_netslab.py")
    first = catalogue["members"][0]
    # A documentary consistency bound, never an observed packet count.
    maximum_classic_records = (first["uncompressed_size_32bit"] - 24) // 16
    assert maximum_classic_records < 1087920
    manifest = json.loads((ROOT / "data/dns_session_source_screen_20261021.json").read_text())
    assert len(manifest["sources"]) == 4 and manifest["qualified_reserved_roles"] == 0
    assert manifest["runtime_changed"] is False and manifest["reserved_ready"] is False
    assert manifest["promoted"] is False and manifest["candidate_scored"] is False
    assert all(all(role is None for role in source["roles"].values()) for source in manifest["sources"])
    assert manifest["sources"][0]["sha256"] == ac["sha256"]
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_text())
    assert len(protected) == 130
    actual = {name: digest(ROOT / name) for name in protected}
    assert actual == protected
    save("integrity-after.json", actual)
    pattern = re.compile(r"(?<![a-zA-Z0-9_-])(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(?![a-zA-Z0-9_-])")
    labels = set()
    for record in receipts:
        text = (CACHE / record["name"]).read_text(encoding="utf-8", errors="replace")
        labels.update(hashlib.sha256(domain_label(value).encode()).hexdigest()
            for value in pattern.findall(text) if domain_label(value))
    examples = ["maliciousEncryptedCommand.sketchydomain.com", "cisco-update.com", "something.google.com",
        "something.there.google.com", "hidemyself.org", "v1.2008.0000.0010.NRXW4Z3FOI.tunnel.test"]
    labels.update(hashlib.sha256(domain_label(value).encode()).hexdigest() for value in examples)
    save("documentation-exclusions.json", dict(scope="Supplementary current-source and recorded snippet first-label exposures; not a complete final registry",
        canonicalizer="ml.dga.domain_label", labels_sha256=sorted(labels)))
    checks = dict(status="PASS_BOUNDED_SOURCE_SCREEN_ONLY", sources_screened=4,
        document_receipts=len(receipts), publisher_document_checksum_verified=True,
        pinned_git_documents=2, protected_originals_matching=len(protected),
        capture_downloads=1, capture_bytes=ac["bytes"], capture_publisher_sha256_verified=True,
        supported_native_headers=1, archive_members_inventoried=len(catalogue["members"]),
        archive_metadata_range_bytes=sum(row["length"] for row in catalogue["ranges"]),
        benign_runs_documented=2, benign_native_headers_verified=0,
        first_benign_claimed_packets=1087920, first_benign_classic_header_only_record_upper_bound=maximum_classic_records,
        candidate_scored=False, packet_records_parsed=0, qualified_reserved_roles=0,
        reserved_ready=False, release_ready=False)
    save("checks.json", checks)
    print(json.dumps(checks))

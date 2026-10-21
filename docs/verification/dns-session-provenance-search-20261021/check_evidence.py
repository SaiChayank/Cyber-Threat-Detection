"""Offline documentary integrity and preservation checks, without inference."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / "data/raw/dns-session-provenance-documents-20261021"
sys.path.insert(0, str(ROOT))
from datasets.score_dns_tunnel import load_contract


def digest(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with path.open("rb") as stream:
        while block := stream.read(1048576):
            h.update(block)
    return h.hexdigest()


def main():
    records = []
    for path in HERE.glob("*retrievals.json"):
        records.extend(json.loads(path.read_bytes()))
    success = [r for r in records if r.get("status") == 200]
    failed = [r for r in records if r.get("error")]
    assert len(records) == 32 and len(success) == 29 and len(failed) == 3
    for r in success:
        path = CACHE / r["name"]
        assert path.stat().st_size == r["bytes"] and digest(path) == r["sha256"]
    assert json.loads((CACHE / "korving-issue.json").read_bytes())["comments"] == 0
    assert json.loads((CACHE / "korving-comments.json").read_bytes()) == []
    root = json.loads((CACHE / "splunk-root.json").read_bytes())
    blobs = {r["path"]: r["sha"] for r in root["tree"]}
    pairs = [("splunk-readme.md", blobs["README.md"]), ("splunk-license.txt", blobs["LICENSE"])]
    trees = {}
    for name, prefix in [("splunk-t1071-tree.json", "T1071.004"),
            ("splunk-t1048-tree.json", "T1048"), ("splunk-t1048-003-tree.json", "T1048.003")]:
        tree = json.loads((CACHE / name).read_bytes())
        assert tree["truncated"] is False
        trees.update({prefix + "/" + r["path"]: r["sha"] for r in tree["tree"] if r["type"] == "blob"})
    for name, url in json.loads((HERE / "sixth-selection.json").read_bytes()):
        remote = url.split("/datasets/attack_techniques/", 1)[1]
        pairs.append((name, trees[remote]))
    for name, expected in pairs:
        b = (CACHE / name).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest() == expected
    acquisition = json.loads((HERE / "ait-acquisition.json").read_bytes())
    artifact = ROOT / acquisition["artifact"]
    assert artifact.stat().st_size == 522084364
    assert digest(artifact) == acquisition["sha256"] == "51a03f51daea0fbbdcfe9b8abe0dbbe10633716f4f98074f861204a162ee1978"
    assert digest(artifact, "md5") == acquisition["md5"] == "abb43a46c70939ad9f98669e3510d2b7"
    catalogue = json.loads((HERE / "ait-catalogue-location.json").read_bytes())
    assert digest(ROOT / catalogue["cache"]) == catalogue["sha256"]
    assert len(json.loads((ROOT / catalogue["cache"]).read_bytes())) == catalogue["member_count"] == 14898
    metadata = [r for r in acquisition["metadata"] if r["present"]]
    metadata += json.loads((HERE / "ait-corrected-metadata.json").read_bytes())
    metadata += [json.loads((HERE / "ait-receiver-metadata.json").read_bytes())]
    for r in metadata:
        assert (ROOT / r["cache"]).stat().st_size == r["bytes"]
        assert digest(ROOT / r["cache"]) == r["sha256"]
    summary = json.loads((HERE / "ait-receiver-summary.json").read_bytes())
    assert summary["received_events"] == 19954 and summary["saved_file_events"] == 31
    assert summary["received_before_simulation"] == 2306 and summary["received_in_simulation"] == 17648
    assert summary["independent_session_count"] is None and summary["role"] is None
    contract = load_contract()
    assert not contract["candidate_runtime_default_enabled"]
    assert not contract["scoring_controls"]["reserved_set_ready"]
    assert contract["scoring_controls"]["reserved_manifest"] is None
    assert not (ROOT / "data/dns_tunnel_reserved_pass.json").exists()
    for name, expected in {
        "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap": "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd",
        "data/raw/burgos-benign-intake-20261021/benign_first_cap.pcap": "f1b0e48cfdbdd38a7701c99b364ed0bd70521224402a9d96eeac7b0dd9845e57"}.items():
        assert digest(ROOT / name) == expected
    for package in ("dns-public-session-screen-20261021", "burgos-benign-verification-20261021", "dns-accuracy-check-20261021"):
        directory = HERE.parent / package
        assert digest(directory / "freeze.json") == (directory / "freeze.sha256").read_text().strip()
        for name, expected in json.loads((directory / "freeze.json").read_bytes())["files"].items():
            assert digest(ROOT / name) == expected
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_bytes())
    assert len(protected) == 130 and {name: digest(ROOT / name) for name in protected} == protected
    manifest = json.loads((ROOT / "data/dns_session_provenance_search_20261021.json").read_bytes())
    assert len(manifest["sources"]) == 4 and all(s["role"] is None for s in manifest["sources"])
    assert manifest["qualified_reserved_roles"] == 0 and not manifest["candidate_scored"]
    result = dict(status="PASS_METADATA_INTAKE_ONLY_FORMAL_DATA_BLOCKED", document_receipts_verified=len(success),
        retrieval_failures_disclosed=len(failed), git_blobs_verified=len(pairs), new_archive_bytes=artifact.stat().st_size,
        full_publisher_archive_checksum_verified=True, metadata_receipts_verified=len(metadata),
        protected_originals_matching=130, prior_acquired_captures_unchanged=2, prior_frozen_packages_unchanged=3,
        frozen_contract_source_pins=len(contract["source_sha256"]), independent_accuracy="NOT_ESTABLISHED",
        runtime_changed=False, reserved_pass_consumed=False, qualified_reserved_roles=0,
        candidate_promoted=False, release_ready=False)
    (HERE / "checks.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps(result))


if __name__ == "__main__":
    main()

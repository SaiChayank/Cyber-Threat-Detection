"""Offline join reproducibility, input identity and unchanged-runtime checks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from datasets.score_dns_tunnel import load_contract, REQUIRED_EVENT_FIELDS


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    archive_path = ROOT / "data/raw/ait-dns-intake-20261021/russellmitchell_no-pcaps.zip"
    assert sha(archive_path) == "51a03f51daea0fbbdcfe9b8abe0dbbe10633716f4f98074f861204a162ee1978"
    receipts = []
    for name in ("stage-a-receipts.json", "stage-a2-receipt.json", "stage-a3-receipts.json", "stage-a4-receipt.json", "stage-b-receipt.json"):
        r = json.loads((HERE / name).read_bytes())
        receipts.extend(r if isinstance(r, list) else [r])
    assert len(receipts) == 14
    with zipfile.ZipFile(archive_path) as archive:
        for r in receipts:
            source = ROOT / r["cache"]
            assert source.stat().st_size == r["bytes"] and sha(source) == r["sha256"]
            info = archive.getinfo(r["member"])
            assert info.file_size == r["bytes"] and f"{info.CRC:08x}" == r["crc32"]
            assert hashlib.sha256(archive.read(info)).hexdigest() == r["sha256"]
    metadata = (ROOT / "data/raw/dns-session-provenance-documents-20261021/ait-corrected-1.yaml").read_text(encoding="utf-8")
    for host, ip in (("internal_share", "10.143.0.103"), ("inet-firewall", "172.19.128.1")):
        section = re.search(r"^" + re.escape(host) + r":\n(.*?)(?=^\S|\Z)", metadata, re.M | re.S)[1]
        assert f'  default_ipv4_address: {ip}\n' in section and '  timezone: UTC\n' in section
    join = module("verify_ait_join", HERE / "diagnose_join.py")
    saved = json.loads((HERE / "join-results.json").read_bytes())
    assert saved["diagnostic_source_sha256"] == sha(HERE / "diagnose_join.py")
    for name, expected in saved["input_sha256"].items():
        assert sha(ROOT / name) == expected
    receiver_path = ROOT / "data/raw/dns-session-provenance-documents-20261021/ait-receiver-metadata.log"
    receiver = [json.loads(row) for row in receiver_path.read_text(encoding="utf-8").splitlines() if row.strip()]
    with (ROOT / "data/raw/ait-session-join-20261021/dnsmasq-original.log").open(encoding="utf-8") as stream:
        reproduced = join.summarize(stream, receiver)
    assert reproduced == {k: v for k, v in saved.items() if k not in ("input_sha256", "diagnostic_source_sha256")}
    assert saved["counts"]["source_lines"] == 275900
    assert saved["counts"]["complete_client_questions"] == 81277
    assert saved["counts"]["non_query_records"] == 194623
    assert saved["namespace_sources"] == {"10.143.0.103": 17693}
    assert saved["namespace_qtypes"] == {"A": 17693}
    assert saved["marker_status_counts"] == {"UNMATCHED": 11, "EXACT_MARKER_JOIN": 20}
    assert all(not row["receiver_in_simulation"] for row in saved["markers"] if row["status"] == "UNMATCHED")
    context = module("verify_ait_context", HERE / "summarize_benign_context.py")
    actors = json.loads((HERE / "benign-context.json").read_bytes())["actors"]
    for file, expected in zip(("metadata-4.log", "benign-employee-1.log"), actors):
        rows = [json.loads(r) for r in (ROOT / "data/raw/ait-session-join-20261021" / file).read_text(encoding="utf-8").splitlines() if r.strip()]
        assert context.summarize(rows, expected["source"]) == expected
    assert actors[0]["records_in_dns_observation_window"] == 0
    assert actors[1]["records_in_dns_observation_window"] == 7493
    manifest = json.loads((ROOT / "data/dns_ait_session_qualification_20261021.json").read_bytes())
    observed = set(manifest["capability"]["observed_runtime_event_fields"])
    assert REQUIRED_EVENT_FIELDS - observed == set(manifest["capability"]["unobserved_required_runtime_event_fields"]) == {"dst_ip", "protocol", "dst_port"}
    annotations = json.loads((HERE / "transfer-associations.json").read_bytes())["annotations"]
    assert len(annotations) == 20 and all(not row["independent_session"] for row in annotations)
    assert manifest["source"]["all_related_exports_excluded_from_reserved"]
    assert manifest["reserved"]["qualified_roles"] == 0 and not manifest["metrics"]["detector_scored"]
    contract = load_contract()
    assert not contract["candidate_runtime_default_enabled"] and not contract["scoring_controls"]["reserved_set_ready"]
    assert contract["scoring_controls"]["reserved_manifest"] is None
    assert not (ROOT / "data/dns_tunnel_reserved_pass.json").exists()
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_bytes())
    assert len(protected) == 130 and {name: sha(ROOT / name) for name in protected} == protected
    for package in ("dns-public-session-screen-20261021", "burgos-benign-verification-20261021", "dns-accuracy-check-20261021", "dns-session-provenance-search-20261021"):
        directory = HERE.parent / package
        assert sha(directory / "freeze.json") == (directory / "freeze.sha256").read_text().strip()
        assert all(sha(ROOT / name) == expected for name, expected in json.loads((directory / "freeze.json").read_bytes())["files"].items())
    for name, expected in {
        "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap": "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd",
        "data/raw/burgos-benign-intake-20261021/benign_first_cap.pcap": "f1b0e48cfdbdd38a7701c99b364ed0bd70521224402a9d96eeac7b0dd9845e57"}.items():
        assert sha(ROOT / name) == expected
    checks = dict(status="PASS_DEVELOPMENT_SOURCE_JOIN_FORMAL_EVALUATION_BLOCKED", new_input_receipts_verified=14,
        source_archive_unchanged=True, original_dns_question_records=81277, original_receiver_marker_joins=20,
        out_of_window_receiver_markers=11, reserved_sessions_qualified=0, independent_accuracy="NOT_ESTABLISHED",
        protected_originals_matching=130, previous_frozen_packages_unchanged=4, previous_captures_unchanged=2,
        contract_source_pins_unchanged=len(contract["source_sha256"]), detector_scored=False,
        reserved_pass_consumed=False, candidate_promoted=False, runtime_changed=False)
    (HERE / "checks.json").write_bytes((json.dumps(checks, indent=2) + "\n").encode())
    print(json.dumps(checks))


if __name__ == "__main__":
    main()

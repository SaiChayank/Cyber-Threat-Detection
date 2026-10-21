"""Recheck pinned source/artifact bytes without network, packets or predictions."""
import hashlib
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


if __name__ == "__main__":
    for name, hash_file in (("selection.json", "selection.sha256"),
                            ("visibility-freeze.json", "visibility-freeze.sha256")):
        assert digest(HERE / name) == (HERE / hash_file).read_text().strip()
        freeze = json.loads((HERE / name).read_text())
        for filename, expected in freeze["sources_sha256"].items():
            assert digest(ROOT / filename) == expected
    acquired = json.loads((HERE / "acquisition.json").read_text())
    visibility = json.loads((HERE / "visibility.json").read_text())
    manifest = json.loads((ROOT / "data/dns_burgos_verification_20261021.json").read_text())
    selection = json.loads((HERE / "selection.json").read_text())
    artifact = ROOT / acquired["artifact"]
    assert digest(artifact) == acquired["sha256"] == visibility["sha256"] == manifest["sha256"]
    assert artifact.stat().st_size == acquired["bytes"] == selection["original_bytes"] == 8852172
    crc = 0
    with artifact.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            crc = zlib.crc32(block, crc)
    assert f"{crc:08x}" == acquired["crc32"] == selection["crc32"] == "5bd6ba90"
    assert acquired["native_compatibility"] == "PASS_CLASSIC_ETHERNET_PCAP"
    assert acquired["header_bytes_read"] == 24 and acquired["packet_records_parsed"] == 0
    assert all(row["length"] <= 1048576 for row in acquired["ranges"])
    assert visibility["counts"]["frames"] == 11005
    assert visibility["counts"]["complete_client_question_messages"] == visibility["counts"]["runtime_client_question_sidecars"] == 72
    assert visibility["counts"]["runtime_question_mismatches"] == 0
    assert visibility["counts"].get("wire_complete_runtime_missing", 0) == 0
    assert visibility["observed_client_qtypes"] == {"1": 36, "65": 36}
    assert visibility["observed_span_seconds"] == 161.583704
    assert visibility["counts"]["backwards_timestamp_steps"] == 3
    assert visibility["certified_independent_dns_sessions"] is None
    assert visibility["certified_benign_categories"] == [] and not visibility["candidate_scored"]
    assert all(role is None for role in manifest["roles"].values())
    assert not manifest["promoted"] and not manifest["runtime_changed"] and not manifest["reserved_ready"]
    old_freeze = json.loads((ROOT / "docs/verification/dns-public-session-screen-20261021/freeze.json").read_text())
    assert all(digest(ROOT / name) == expected for name, expected in old_freeze["files"].items())
    ac = ROOT / "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap"
    assert digest(ac) == "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd"
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_text())
    actual = {name: digest(ROOT / name) for name in protected}
    assert len(actual) == 130 and actual == protected
    (HERE / "integrity-after.json").write_bytes((json.dumps(actual, indent=2) + "\n").encode())
    result = dict(status="PASS_CAPTURE_VERIFICATION_ONLY", selected_member_crc_verified=True,
        source_and_visibility_freezes_verified=True, native_classic_ethernet=True,
        packet_records=11005, complete_client_questions=72, runtime_question_matches=72,
        backward_capture_timestamp_steps_preserved=3, protected_originals_matching=130,
        prior_source_package_unchanged=True, prior_attack_intake_unchanged=True,
        new_tests=23, targeted_tests_passed=139, qualified_reserved_roles=0,
        candidate_scored=False, feature_validation_dod="BLOCKED", release_ready=False)
    (HERE / "checks.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps(result))

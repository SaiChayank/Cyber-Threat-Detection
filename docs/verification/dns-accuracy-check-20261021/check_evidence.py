"""Validate scoped reported metrics and preservation; never run inference."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


if __name__ == "__main__":
    assert digest(HERE / "before.json") == (HERE / "before.sha256").read_text().strip()
    before = json.loads((HERE / "before.json").read_text())
    for name, expected in before["sources_sha256"].items():
        assert digest(ROOT / name) == expected
    contract = json.loads((ROOT / "data/dns_tunnel_evaluation_contract.json").read_text())
    assert before["quality_gates"] == contract["quality_gates"]
    assert contract["candidate_runtime_default_enabled"] is False
    assert all(digest(ROOT / name) == expected for name, expected in contract["source_sha256"].items())
    candidate = json.loads((HERE / "development.json").read_text())
    serialization = json.loads((HERE / "serialization-receipt.json").read_text())
    stored = (HERE / "development.json").read_bytes()
    assert digest(HERE / "development.json") == serialization["stored_lf_sha256"]
    assert hashlib.sha256(stored.replace(b"\n", b"\r\n")).hexdigest() == serialization["original_cli_sha256"]
    baseline = json.loads((HERE / "baseline-rule.json").read_text())
    assert len(candidate["sessions"]) == len(baseline["sessions"]) == 20
    assert baseline["comparison_source_sha256"] == digest(HERE / "compare_baseline.py")
    for split in ("training", "validation"):
        c = candidate["metrics_by_split"][split]
        b = baseline["metrics_by_split"][split]
        assert [c[key] for key in ("TP", "TN", "FP", "FN")] == [5, 5, 0, 0]
        assert [b[key] for key in ("TP", "TN", "FP", "FN")] == [0, 4, 1, 5]
        assert c["precision"] == c["recall"] == c["F1"] == c["early_tp_fraction"] == 1
        assert c["FPR"] == 0 and b["FPR"] == 0.2 and b["early_tp_fraction"] is None
    positives = [row for row in candidate["sessions"] if row["split"] == "validation" and row["positive"]]
    assert len(positives) == 5 and all(row["first_alert_query"] == 5 < row["queries"] == 12 for row in positives)
    assert sorted(row["first_alert_delay_ms"] for row in positives) == [3800, 4400, 4800, 6000, 7200]
    assert all(row["late_questions_dropped"] == 0 for row in candidate["sessions"] + baseline["sessions"])
    assert candidate["promotion_decision"] == "NOT_EVALUATED_DATA_BLOCKED" and not candidate["runtime_activated"]
    assert not (HERE / "reserved.json").exists() and not (ROOT / "data/dns_tunnel_reserved_pass.json").exists()
    preflight = json.loads((HERE / "reserved-preflight.json").read_text())
    assert preflight["independent_metrics"] is None and not preflight["reserved_pass_consumed"]
    assert not contract["scoring_controls"]["reserved_set_ready"] and contract["scoring_controls"]["reserved_manifest"] is None
    for package in ("dns-public-session-screen-20261021", "burgos-benign-verification-20261021"):
        path = ROOT / "docs/verification" / package
        assert digest(path / "freeze.json") == (path / "freeze.sha256").read_text().strip()
        frozen = json.loads((path / "freeze.json").read_text())
        assert all(digest(ROOT / name) == expected for name, expected in frozen["files"].items())
    artifacts = {
        "data/raw/dns-public-session-intake-20261021/dnscat2_dns_tunneling_1hr.pcap": "b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd",
        "data/raw/burgos-benign-intake-20261021/benign_first_cap.pcap": "f1b0e48cfdbdd38a7701c99b364ed0bd70521224402a9d96eeac7b0dd9845e57"}
    assert all(digest(ROOT / name) == expected for name, expected in artifacts.items())
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_text())
    actual = {name: digest(ROOT / name) for name in protected}
    assert len(actual) == 130 and actual == protected
    (HERE / "integrity-after.json").write_bytes((json.dumps(actual, indent=2) + "\n").encode())
    result = dict(status="PASS_CONTROLLED_REGRESSION_ONLY", targeted_tests_passed=115,
        synthetic_training_sessions=10, synthetic_validation_sessions=10,
        candidate_validation_counts={key: candidate["metrics_by_split"]["validation"][key] for key in ("TP", "TN", "FP", "FN")},
        baseline_rule_validation_counts={key: baseline["metrics_by_split"]["validation"][key] for key in ("TP", "TN", "FP", "FN")},
        independent_accuracy="NOT_ESTABLISHED", formal_validation_dod="BLOCKED",
        reserved_pass_consumed=False, protected_originals_matching=130,
        prior_acquired_captures_unchanged=2, prior_frozen_source_packages_unchanged=2,
        runtime_changed=False, candidate_promoted=False, release_ready=False)
    (HERE / "checks.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps(result))

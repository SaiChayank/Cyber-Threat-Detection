"""Same-session controlled rule comparison; no public captures or model changes."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from datasets.dns_tunnel_development import SCENARIOS, events
from datasets.score_dns_tunnel import load_contract, score_session, summarize
from detection.pipeline import Pipeline


if __name__ == "__main__":
    before = json.loads((HERE / "before.json").read_text())
    assert hashlib.sha256((HERE / "before.json").read_bytes()).hexdigest() == (HERE / "before.sha256").read_text().strip()
    assert all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == value
               for path, value in before["sources_sha256"].items())
    contract = load_contract()
    output = HERE / "baseline-rule.json"
    if output.exists():
        raise FileExistsError("Preserve prior baseline comparison")
    rows = []
    for scenario in SCENARIOS:
        name, split, positive, pattern, _, _, namespace, _ = scenario
        spec = dict(session_id=name, positive=positive, tool="synthetic" if positive else None,
                    benign_category=pattern if not positive else None,
                    namespace=namespace, source_ip="192.0.2.10")
        result = score_session(spec, (event.model_dump(mode="json") for event in events(scenario)),
            contract["quality_gates"], pipeline_factory=lambda: Pipeline(dns_tunnel_candidate=False))
        rows.append(result | dict(split=split))
    result = dict(scope="Already exposed synthetic rule-only baseline; model forced BENIGN identically to candidate arm; not full deployed hybrid or independent accuracy",
        comparison_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_pins=contract["source_sha256"], runtime_changed=False, public_capture_scored=False,
        reserved_pass_consumed=False, sessions=rows,
        metrics_by_split={split: summarize([row for row in rows if row["split"] == split], contract["quality_gates"])
                          for split in ("training", "validation")})
    output.write_bytes((json.dumps(result, indent=2, allow_nan=False) + "\n").encode())
    print(json.dumps(result["metrics_by_split"]))

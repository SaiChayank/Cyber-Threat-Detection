"""Describe original application execution context, without assigning DNS labels."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def summarize(rows, source="gather/internal_employee_0/logs/sm.log"):
    start = datetime(2022, 1, 21, tzinfo=timezone.utc).timestamp()
    end = datetime(2022, 1, 25, tzinfo=timezone.utc).timestamp()
    return dict(source=source, records=len(rows),
        original_run_id_count=len({str(r.get("run")) for r in rows}),
        state_counts=dict(Counter(str(r.get("current_state", "MISSING")) for r in rows)),
        transition_counts=dict(Counter(str(r.get("transition", "MISSING")) for r in rows)),
        original_timestamp_min=min(r["timestamp"] for r in rows),
        original_timestamp_max=max(r["timestamp"] for r in rows),
        records_in_dns_observation_window=sum(start <= r["timestamp"] < end for r in rows),
        completed_mail_messages=sum(r.get("message") == "Sent mail" for r in rows),
        exception_records=sum("exception" in r for r in rows),
        dns_question_or_transaction_join_fields_present=any(
            any(k in r for k in ("dns_name", "dns_type", "dns_question", "dns_transaction_id")) for r in rows),
        independent_benign_sessions=None, qualified_benign_categories=[],
        role="development_context_only", payload_or_credentials_published=False)


if __name__ == "__main__":
    result = dict(scope="Original application context, not DNS/session labels", actors=[])
    for file, member in [("metadata-4.log", "gather/internal_employee_0/logs/sm.log"),
            ("benign-employee-1.log", "gather/internal_employee_1/logs/sm.log")]:
        raw = ROOT / "data/raw/ait-session-join-20261021" / file
        rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines() if line.strip()]
        result["actors"].append(summarize(rows, member))
    (HERE / "benign-context.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps([{k: v for k, v in actor.items() if k not in ("state_counts", "transition_counts")} for actor in result["actors"]]))

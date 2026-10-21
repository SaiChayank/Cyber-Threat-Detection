"""Summarize original receiver execution metadata, never resolver observations."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def summarize(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    start = datetime(2022, 1, 21, tzinfo=timezone.utc).timestamp()
    end = datetime(2022, 1, 25, tzinfo=timezone.utc).timestamp()
    received = [r for r in rows if r.get("event") == "Received data"]
    files = defaultdict(list)
    for r in received:
        files[r.get("file")].append(r["timestamp"])
    saved = [r for r in rows if r.get("event") == "Saved file"]
    def utc(value):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    return dict(rows=len(rows), source_sha256=hashlib.sha256(raw).hexdigest(),
        event_counts=dict(Counter(r.get("event") for r in rows)),
        field_counts=dict(Counter(k for r in rows for k in r)), received_events=len(received),
        first_received_utc=utc(min(r["timestamp"] for r in received)),
        last_received_utc=utc(max(r["timestamp"] for r in received)),
        received_before_simulation=sum(r["timestamp"] < start for r in received),
        received_in_simulation=sum(start <= r["timestamp"] < end for r in received),
        files_referenced=len(files), saved_file_events=len(saved),
        distinct_saved_file_names=len({r["file"] for r in saved}),
        file_metadata=[dict(file_id_sha256=hashlib.sha256(str(f).encode()).hexdigest(),
            first_utc=utc(min(times)), last_utc=utc(max(times)), events=len(times),
            first_receive_within_simulation=start <= min(times) < end,
            last_receive_within_simulation=start <= max(times) < end) for f, times in files.items()],
        independent_session_count=None, role=None, dns_questions_read=0, candidate_scored=False)


if __name__ == "__main__":
    source = ROOT / "data/raw/dns-session-provenance-documents-20261021/ait-receiver-metadata.log"
    raw = source.read_bytes()
    receipt = json.loads((HERE / "ait-receiver-metadata.json").read_bytes())
    assert len(raw) == receipt["bytes"] and hashlib.sha256(raw).hexdigest() == receipt["sha256"]
    result = summarize(raw)
    (HERE / "ait-receiver-summary.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({k: v for k, v in result.items() if k not in ("file_metadata", "field_counts")}))

# Current source scoped performance refresh

20 October 2026 IST; baseline `a96a4ef`. No detector or benchmark implementation
change. Preserve the old canonical benchmark reports in this dated package before
updating their latest pointers. Use the existing commands, synthetic workload and
disposable stores; never open original analyst history.

Run sequentially after owned test services stopped: >=20,000 metadata events in
the existing core + SQLite runner, then >=100 deterministic API/persistence/direct
SSE alerts. Gates unchanged: >=2,000 metadata events/sec; processing + SQLite
p95 <50 ms; loopback API-to-SSE p95 <1,000 ms; every expected record must match.
Record actual hardware/Python/event and alert counts/elapsed/p50/p95/p99 as supplied
by the declared runners, exact source/model hashes and exclusions. No retries to
cherry-pick better numbers; diagnose a failed gate before changing anything.

Core excludes capture/HTTP/SSE/rendering; delivery excludes capture/Next/browser/
concurrent subscribers. Do not call either raw-capture-to-browser capacity or
public-data accuracy. If both pass, update only actually rerun report pointers and
documentation, verify API benchmark output equals the saved core report, retain
130 protected originals, freeze and commit. This is current scoped evidence while
research gates are unresolved, not final-release acceptance.

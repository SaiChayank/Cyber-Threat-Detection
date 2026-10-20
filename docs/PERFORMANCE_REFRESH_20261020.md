# Current scoped performance evidence

20 October 2026 IST; baseline `a96a4ef`. **Scoped performance DoD PASS.**
Research/data quality blockers remain; this does not declare the final release.

Inspected declared runners, existing gates, report currency, source/model hashes,
API benchmark route and earlier results. Ran each declared workload once,
sequentially after owned verification services stopped. No optimization, caching,
new dependency, detector/artifact change or alert-history access.

## Actual measurements

- **Core + SQLite:** 20,000 synthetic metadata events, 1,170 committed alerts,
  5.266722 seconds; **3,797.43 events/sec**. Per-event processing + persistence
  p50 **0.1862 ms**, p95 **1.0117 ms**. Gates >=2,000/sec and p95 <50 ms pass.
  Scope includes core event processing and SQLite alert commits; excludes capture,
  HTTP, SSE and browser rendering. Percentile convention is the existing sorted
  zero-based floor(n*fraction), not a newly substituted calculation.
- **Direct loopback API -> SQLite -> SSE:** 100 accepted, persisted and delivered
  complete records, all IDs/data matching; elapsed submission-through-final-receipt
  **0.771080 seconds**. p50 **143.02 ms**, p95 **245.94 ms**, p99 **259.30 ms**;
  nearest-rank percentiles. Gate p95 <1,000 ms passes. Cursor resume and exact
  durable reopening after API shutdown pass. Scope excludes raw capture, Next.js
  proxy, browser rendering and concurrent subscribers. Serial batch rate is not
  sustained capacity.

Environment: Python **3.13.5**, Windows/AMD64, AMD Ryzen 7 8845HS, **16 logical
CPUs**, **16,356,941,824 bytes** OS-visible physical memory. Exact platform,
UTC timestamps and hardware fields are in the reports; storage hardware was not
changed or independently remeasured here. The normal local machine is not an
isolated hardware benchmark laboratory; do not infer a causal speed improvement.

## Currency, preservation and checks

Only actually rerun canonical reports `benchmarks/latest.json` and
`benchmarks/delivery_latest.json` are refreshed. Their previous exact bytes are
preserved portably as base64 plus SHA256 in
[previous reports](verification/performance-refresh-20261020/previous-reports.json);
unmodified raw copies remain locally under ignored data/raw. New reports normalize
CRLF to LF only, recorded with generated/committed hashes; numerical values do not
change. No historical measured report is silently rewritten as a new measurement.

The old 1 October canonical core was 5,649.91/sec/p95 0.8416 ms; old canonical
delivery p95 was 240.27 ms. Those used earlier runtime hashes and are not a
controlled before/after comparison. Most recent source-matching replay-error
delivery p95 was 243.91 ms. Current gates pass without tuning or repeated runs;
run-to-run variation is not attributed to a particular stage or optimization.

Every current runtime/benchmark/model report hash matches source bytes. An isolated
TestClient GET /api/benchmark returns exactly the new core report and an empty
disposable alert history; no mock response. All 130 current protected originals
remain unchanged. No application test/build rerun is claimed for this reports-only
task; the preceding 593-test/typecheck/build and responsive evidence remain dated.
No detector-quality, raw-packet throughput, multi-client load or CPU/memory-utilization
measurement is inferred from these workloads.

[Protocol, commands, logs and checks](verification/performance-refresh-20261020/)
freeze this successful scope. The ordinary Monitor now receives the current saved
core report through its existing API. Existing failed candidates remain disabled.

**Exactly next:** reproduce handling of syntactically invalid/non-object stored
alert JSON using a disposable database. Correct only an observed read/recovery
defect; preserve original history and all detector/model contracts.

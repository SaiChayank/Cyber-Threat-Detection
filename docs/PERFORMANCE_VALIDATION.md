# Final performance evidence

**20 October 2026 scoped refresh:** [Current measured evidence](PERFORMANCE_REFRESH_20261020.md)
records 20,000 events/1,170 commits, 3,797.43 metadata events/sec, core + SQLite
p50 0.1862 ms/p95 1.0117 ms; direct API/SQLite/SSE 100/100, p50 143.02 ms,
p95 245.94 ms/p99 259.30 ms. All declared gates pass in their original scopes.
Canonical latest reports are refreshed; previous exact bytes are retained. This
supersedes performance currency only, not required detector-quality blockers or
final release acceptance. Historical sections below retain their original dates.

**3 October 2026 recovery follow-up:** current shared runtime measurements are in
[event recovery validation](EVENT_RECOVERY_VALIDATION.md): core 4,072.43 events/s,
processing+SQLite p95 0.9228 ms; API-to-SSE 100/100, p95 248.92 ms. Gates pass with
disclosed staging cost. Older reports below retain their recorded numbers/dates;
their runtime source hashes no longer match the changed recovery implementation.

Historical documentation audit **2 October 2026**: the saved1 October core/delivery values,
timestamps and source/model/script hashes matched the runtime audited on that date.
No benchmark was rerun in that documentation audit. Older numbers in detector/reliability documents
are historical at their recorded revisions; this was the latest measured performance
evidence, not a newly completed clean-install benchmark. See
[report index](STREAMING_VALIDATION.md) and
[audit](verification/documentation-audit.json).

**Later clean-checkout release audit:** [Fresh core report](verification/release-audit/core-benchmark.json)
records 20,000 events/1,170 alerts,3.200962s,6,248.12 events/s, p50 0.0883 ms and
p95 0.8070 ms. [Fresh delivery report](verification/release-audit/api-sse-benchmark.json)
records 100/100 alerts, p50 149.52 ms, p95 247.48 ms, p99 259.10 ms. Both gates pass.
These new measurements were taken sequentially after stopping owned services;
the older reports below remain unchanged. Scope/hardware and the NOT READY
quality decision are in [Final release audit](FINAL_RELEASE_AUDIT.md).

Benchmarks rerun sequentially on **1 October 2026**, after inspecting the current
runtime, benchmark scripts, existing verification tests, saved reports and declared
completion gates. This task updates performance evidence only; prior UI work remains
in the working tree, and detector behavior/artifacts were not modified.

## Frozen gates and measured results

The unchanged core gates are >=2,000 metadata events/sec and processing + SQLite
p95 <50 ms. The unchanged loopback API-to-SSE gate is p95 <1,000 ms, with every
expected alert accepted, persisted and delivered correctly.

| Measurement | Core + SQLite | Loopback API → SQLite → SSE |
|---|---:|---:|
| Report time (UTC) | 2026-10-01 12:10:58 | 2026-10-01 12:11:03 |
| Input events | 20,000 | 100 |
| Alert count | 1,170 committed alerts | 100 accepted / 100 persisted / 100 delivered |
| Timed elapsed | 3.539879 s | 0.509684 s |
| Observed event rate | 5,649.91 metadata events/sec | 196.20 events/sec in this serial short batch |
| p50 | 0.0971 ms, processing + commit | 129.06 ms, API-to-SSE |
| p95 | 0.8416 ms, processing + commit | 240.27 ms, API-to-SSE |
| p99 | Not collected by declared core script | 251.66 ms |
| API-response p50 / p95 | Outside scope | 4.76 / 5.75 ms |
| Gate result | **PASS** throughput and latency | **PASS** latency, complete record delivery and durability |

Core telemetry reports 20,000 processed events, zero late events and zero state
evictions. The active conservative DGA guard remains unchanged; DGA and DNS-tunnel
candidates remain disabled. All 100 SSE records match the full API and SQLite
records, including IDs/sequences/evidence; no alert is lost or duplicated. Resume
and durable SQLite reopening also pass. These are functional/performance checks,
not evidence of detector accuracy or malware generalization.

Machine-readable records: `benchmarks/latest.json` and
`benchmarks/delivery_latest.json`. Both include runtime source hashes, frozen model
hash, benchmark script hashes, Python/platform, hardware and explicit timing scope.
All recorded hashes were verified against the current files after the runs.

## Hardware and environment

- HP Victus by HP Gaming Laptop 15-fb2xxx.
- AMD Ryzen 7 8845HS w/ Radeon 780M Graphics: 8 physical cores, 16 logical CPUs;
  AMD64 architecture.
- OS-visible physical RAM: **16,356,941,824 bytes** (approximately 15.23 GiB).
- Local storage model: **MTFDKBA512QFM-1BD1AABHA**, reported disk size
  512,105,932,800 bytes. Both temporary databases use the normal Windows temporary
  directory on this local machine; storage hardware is not replaced or optimized.
- Python **3.13.5** in the existing project `.venv`.
- Platform: **Windows-11-10.0.26300-SP0**.

CPU/RAM are read by `benchmarks/environment.py` before timed work. Laptop model,
physical core count and storage model were additionally read with Windows CIM.
No affinity, power-plan change, CPU-load isolation, cache, new dependency, service or
distributed infrastructure was introduced. These are single-run measurements on a
development laptop; background scheduling and storage variance are not controlled.

## Exact timing scopes

**Core + SQLite:** existing repeated eight-class synthetic metadata template,
including the benign baseline, with the normal `Pipeline` and `AlertStore`. The
overall timed loop includes metadata copying, feature extraction, model/rules,
alert production and each SQLite append/commit. Per-event p50/p95 times start after
the metadata copy and include `Pipeline.process` and any resulting SQLite commits.
Pipeline/template construction, database setup/close and final report creation are
outside the timed loop. There is no HTTP ingestion, PCAP parsing, Next.js proxy,
SSE transport or browser rendering. **This is not raw-capture-to-browser throughput.**

The existing core percentile convention is retained: sorted zero-based index
`floor(n * fraction)` (20,000 observations select indices 10,000 and 19,000).
Delivery retains nearest-rank percentiles, `ceil(n * fraction)` one-based (100
observations select ranks 50, 95 and 99). Gates and sample sizes were not changed.

**API-to-SSE:** one owned loopback FastAPI process, one SSE subscriber and a
temporary SQLite database; 100 serial deterministic high-rate UDP flow summaries.
Each alert latency runs from immediately before its POST to direct receipt of that
alert's SSE data, using a monotonic clock. The batch duration runs from the first
submission through final SSE receipt, after subscriber establishment. It excludes
startup, subsequent verification/resume queries, database reopening and shutdown.
It excludes capture parsing, Next.js proxy, browser rendering, external network
transit and concurrent subscribers. Its short serial batch rate is informational,
not sustained HTTP capacity or a substitute for the core throughput gate.

## Before versus after

| Previously saved → current | Before | After |
|---|---:|---:|
| Core event rate | 6,083.02 events/sec | 5,649.91 events/sec |
| Core elapsed, same 20,000 events | 3.287839 s | 3.539879 s |
| Core p95 | 0.8410 ms | 0.8416 ms |
| Core alert count | 1,170 | 1,170 |
| API-to-SSE p50 | 140.63 ms | 129.06 ms |
| API-to-SSE p95 | 241.57 ms | 240.27 ms |
| API response p95 | 2.84 ms | 5.75 ms |
| Complete API/SQLite/SSE alert count | 100 / 100 / 100 | 100 / 100 / 100 |

The prior core report is dated 30 September 2026, 13:42:22 UTC; prior delivery is
1 October, 02:03:43 UTC. Core throughput is 7.12% lower in this single run, while
core p95 is essentially unchanged and both gates pass comfortably. All six previously
recorded core runtime hashes and the model hash match. The delivery backend source
hash differs; its previously recorded detector/features/store hashes match.

The old reports did not record hardware or the new duration/p50 fields, so matching
CPU/RAM conditions and omitted historical values cannot be asserted. These results
do not establish a detector-caused regression or identify a causal HTTP/SQLite/SSE
stage slowdown. No performance optimization was performed. A future failing gate
must be reproduced and profiled by stage before making an optimization; the current
runs do not justify changing the implementation to improve a number.

## Reproduction, changes and decision

Run sequentially from the repository root:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_delivery_benchmark.py -q
.venv/Scripts/python.exe -m benchmarks.run --events 20000
.venv/Scripts/python.exe -m benchmarks.delivery --events 100
```

Changed files for this task: `benchmarks/run.py`, `benchmarks/delivery.py`, new
`benchmarks/environment.py`, the two rerun JSON reports, this document,
`docs/API_SSE_DELIVERY_VALIDATION.md` and the performance entry in
`docs/COMPLETION_PLAN.md`. Script changes add reporting/provenance only; workload,
percentile methods, acceptance gates and runtime processing are preserved.

Tests added/changed: **none**; no detector defect was fixed. The **3 existing
benchmark verification tests pass**, and both real benchmark runs pass their
checks. The existing analyst database still holds 130 alerts and its file hash is
unchanged. Models, datasets, alert history and unrelated validation reports are
preserved; earlier UI/test reports are not presented as newly rerun here.

**Performance-task Definition of Done: passed** within its measured scopes.
Both reports remain source-matching and meet the gates. Demo preparation subsequently
passed; corrected clean-checkout verification and publication remain pending.
The [completion plan](COMPLETION_PLAN.md) records exact remaining work without
turning performance success into detection-quality or whole-project acceptance.

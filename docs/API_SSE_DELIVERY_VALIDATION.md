# API → SQLite → SSE alert delivery validation

Documentation audited **2 October 2026**. The1 October report and its numbers are
retained, not rerun; runtime/model/benchmark hashes still match. This was the latest
saved direct loopback measurement, not a browser-render or fresh-checkout test.

The subsequent [release-audit measurement](verification/release-audit/api-sse-benchmark.json)
is a fresh isolated-checkout run:100/100 accepted/persisted/delivered alerts,
p50 149.52 ms, p95 247.48 ms, p99 259.10 ms, with durable persistence and resume
verified. The <1,000 ms gate passes. It retains the same direct loopback exclusions;
this document's earlier numerical report remains intact. See
[Final release audit](FINAL_RELEASE_AUDIT.md) for the current overall decision.

Run `python -m benchmarks.delivery --events 100`. The script launches its own
API on 127.0.0.1 with a temporary SQLite file and one SSE subscriber. It submits
100 deterministic, distinct high-rate UDP flow summaries through `POST /api/events`.
Each request must be accepted and return exactly one DDoS alert. For every alert,
the benchmark compares the **entire** API response record to `GET /api/alerts`
and the SSE data record, checks the SSE `id` against the persisted sequence,
and requires unique alert IDs/sequences. It rejects missing, extra or duplicate
records. It also verifies `Last-Event-ID` resume and reopens SQLite after API
shutdown to confirm durable whole-record equality. The temporary database does
not touch analyst alert history. The machine-readable result, runtime hashes and
environment are in `benchmarks/delivery_latest.json`.

Latest run: **1 October 2026, 12:11:03 UTC**, Python **3.13.5** on
Windows 11 build 26300; AMD Ryzen 7 8845HS (8 cores / 16 logical CPUs),
16,356,941,824 bytes of visible physical RAM. Detailed hardware, comparison and
the separately rerun core benchmark are in [Final performance evidence](PERFORMANCE_VALIDATION.md).

| Measurement (latest 1 October 2026 run) | Result | Gate |
|---|---:|---:|
| Accepted / persisted / SSE delivered | 100 / 100 / 100 | 100 / 100 / 100 |
| Durable SQLite readback | 100 matching records | All match |
| Serial batch elapsed, first submission to final SSE receipt | 0.509684 s | Informational |
| Serial batch observed event rate | 196.20 events/sec | Informational; not sustained capacity |
| API-to-SSE p50 | 129.06 ms | Informational |
| API-to-SSE p95 | 240.27 ms | **< 1,000 ms** |
| API-to-SSE p99 | 251.66 ms | Informational |
| API-to-SSE maximum | 252.77 ms | Informational |
| API acceptance p50 | 4.76 ms | Informational |
| API acceptance p95 | 5.75 ms | Informational |

**Gate: pass.** Latency starts immediately before the client sends each API
request and ends when that alert's SSE `data` line is received, using a monotonic
clock. Percentiles use nearest rank (for 100 alerts, ranks 50, 95 and 99). The
earlier saved 29 September run recorded 100/100 and p95 250.09 ms, but its
runtime-source hashes differ and it checked only IDs/sequences, so the two numbers
are contextual rather than a controlled performance comparison.
The immediately preceding saved 1 October run (02:03:43 UTC) recorded 100/100,
p50 140.63 ms and p95 241.57 ms. Its backend source hash differs from the latest
run; the previously recorded shared detector/features/store hashes match. This
comparison does not identify a causal performance change in any individual stage.

Batch timing starts after the SSE subscription is established and ends after all
100 alerts are received. It excludes API startup, record verification, resume checks
and shutdown. Hardware collection and report hashing occur outside that interval.
Serial batch events/sec describes this short workload, not a new throughput gate.

Scope is loopback API ingestion, inference, SQLite commit, polling SSE delivery
and direct client receipt. It excludes raw capture parsing, Next.js proxy,
browser rendering, network transit and multiple simultaneous subscribers.
The workload is serial deterministic alert-producing metadata, not sustained
concurrent production traffic. This result must not be called an end-to-end
capture-to-browser benchmark.

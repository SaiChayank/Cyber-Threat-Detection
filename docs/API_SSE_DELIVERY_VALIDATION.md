# API → SQLite → SSE alert delivery validation

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

| Measurement (1 October 2026 run) | Result | Gate |
|---|---:|---:|
| Accepted / persisted / SSE delivered | 100 / 100 / 100 | 100 / 100 / 100 |
| Durable SQLite readback | 100 matching records | All match |
| API-to-SSE p50 | 140.63 ms | Informational |
| API-to-SSE p95 | 241.57 ms | **< 1,000 ms** |
| API-to-SSE p99 | 251.26 ms | Informational |
| API-to-SSE maximum | 254.50 ms | Informational |
| API acceptance p95 | 2.84 ms | Informational |

**Gate: pass.** Latency starts immediately before the client sends each API
request and ends when that alert's SSE `data` line is received, using a monotonic
clock. Percentiles use nearest rank (for 100 alerts, ranks 50, 95 and 99). The
earlier saved 29 September run recorded 100/100 and p95 250.09 ms, but its
runtime-source hashes differ and it checked only IDs/sequences, so the two numbers
are contextual rather than a controlled performance comparison.

Scope is loopback API ingestion, inference, SQLite commit, polling SSE delivery
and direct client receipt. It excludes raw capture parsing, Next.js proxy,
browser rendering, network transit and multiple simultaneous subscribers.
The workload is serial deterministic alert-producing metadata, not sustained
concurrent production traffic. This result must not be called an end-to-end
capture-to-browser benchmark.

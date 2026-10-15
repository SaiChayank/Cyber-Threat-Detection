# Event retry recovery — 3 October 2026

**Definition of Done: PASSED for the local single-process event path.** Freeze this
correction and its regressions. Publication is pending; overall release remains
NOT READY because the existing detector-quality blockers are unchanged.

## Inspected and reproduced

Inspected the API consume path, pipeline, extractor/rate windows, SQLite store,
SQLite/replay/SSE tests, completion plan, frozen demo and packaging verification.

The old pipeline mutated causal features, processed count, sessions and suppression
before persistence. A locked write returned HTTP 500; retry returned HTTP 200 with
no alert, leaving zero persisted alerts. Failed inference followed by retry counted
two events and reported 2,400 packets/s instead of 1,200. Alerts committed separately,
so later insertion failure could retain only part of an event's batch. Duplicate-ID
errors also left a transaction open.

The before reproduction used preserved packaging snapshot
`43a67cfe830c068d866e6eb064be56857c5dd7fa`, a commit in a temporary repository, with
the same Python environment. This is not a published revision.

## Minimal correction

- Stage ordered maps, the affected source history/byte window, global rate state
  and affected target window. Other source histories and expired read-only buckets
  are shared rather than deep-copied. Ordered eviction and bounded state remain.
- Run unchanged detector logic against staged state. Publish features, sessions,
  suppression, processed count and successful timings only after inference and
  the caller's atomic alert-batch writer succeed.
- `AlertStore.append_many()` uses one SQLite transaction per event. Insertion,
  serialization or commit errors roll back the batch. Existing `append()` delegates
  to it, so duplicate-ID errors release the transaction too.
- The event API logs processing errors and returns sanitized HTTP 503 with retry
  guidance. Replay still reports failure/stops through its existing path. No new
  queue, broker, retry worker or ingestion architecture.
- Processing telemetry continues excluding SQLite time. Benchmarks retain their
  separate core+SQLite and API-to-SSE scopes.

AST comparisons verify unchanged extractor/rate `update()` and detector rules,
model combination, evidence and alert construction. All nine frozen demo traces,
evidence and event positions match exactly. Four source-provenance pins and the
manifest checksum were updated only after this equality check; fixture bytes and
expected outputs were unchanged. The new store version is pinned in the recovery
benchmark reports; it was not an existing demo-manifest provenance entry.

## Tests and measured results

The initial eight regressions failed before implementation. The final targeted
file has **16 passing cases** covering locked writes; feature/inference/alert
errors; partial batches; duplicate IDs; serialization errors; TCP/UDP same-bucket
mutation, expiration/overflow and LRU eviction; failed watermark advancement;
real retry-to-SSE/restart delivery; and timing-scope preservation.

**Full backend: 268 passed, zero failures/skips, one existing Starlette/httpx warning,
72.56 seconds.** TypeScript with incremental cache disabled and the Next.js production
build passed. Existing threat, parser, replay, upload, persistence, SSE, packaging
and demo tests passed. Browser layouts and production startup were not rerun.

| Measurement | Before | After | Gate |
| --- | ---: | ---: | --- |
| Locked retry: persisted alerts | 0 | 1 | One expected alert |
| Inference retry: processed count | 2 | 1 | One accepted event |
| Inference retry: rate evidence | 2,400/s | 1,200/s | Correct observed rate |
| Core+SQLite, 20,000 events | 5,468.00/s | 4,072.43/s | >=2,000/s, passed |
| Core+SQLite p50 | 0.1035 ms | 0.1572 ms | Recorded |
| Core+SQLite p95 | 0.8350 ms | 0.9228 ms | <50 ms, passed |
| Core alert count | 1,170 | 1,170 | Unchanged |
| API-to-SSE delivery | Before not rerun | 100/100 | No loss/mismatch |
| API-to-SSE p50 / p95 / p99 | — | 154.45 / 248.92 / 257.83 ms | p95<1,000 ms, passed |

Windows 11, AMD Ryzen 7 8845HS, 16 logical CPUs, approximately 16.36 GB physical
memory, Python 3.13.5. Core elapsed: before 3.6576 s, after 4.9111 s. Sequential
comparison used the same environment/workload. The before runner's report destination
was redirected in memory without altering its snapshot files. After runners add
only an optional `--output` path, leaving older saved reports untouched.

The single comparison records a **25.52% throughput reduction**, not a statistical
capacity estimate. Instrumentation isolates `FeatureExtractor.fork()` at mean
0.02864 ms, p50 0.02520 ms, p95 0.04060 ms across 20,000 observations/33 active
sources. It accounts for part of the overhead; session copying/transaction wrapper
and run variation also contribute. Gates pass, so no further optimization is made.
Full-cardinality/concurrent workloads were not measured.

Core excludes capture, HTTP, SSE and rendering; the existing runner persists through
`append()`. Delivery exercises the actual atomic API callback and excludes Next.js,
browser, capture and concurrent subscribers. Neither is capture-to-browser throughput
or field accuracy. All seven model payloads/sidecars, disabled candidates, demo inputs,
DGA plans, analyst DB and original Git index are preserved. No training, reserved-data
inspection or promotion occurred.

[Machine-readable evidence](verification/event-recovery-20261003/report.json) pins
the current code/tests/models, before/after metrics, profiling and test/build logs.

## Reproduce and limitations

```powershell
.venv/Scripts/python.exe -B -m pytest tests/test_event_recovery.py -q -p no:cacheprovider
.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider
npm run typecheck --workspace frontend -- --incremental false
npm run build
.venv/Scripts/python.exe -B -m replay.demo_pack
.venv/Scripts/python.exe -B -m benchmarks.run --events 20000 --output deployment/recovery-core.json
.venv/Scripts/python.exe -B -m benchmarks.delivery --events 100 --output deployment/recovery-delivery.json
```

- Retry failed inputs **before accepting later observations**, preserving causal
  order. Existing explicit late drops remain; there is no durable raw-event queue.
- Successful duplicate input remains a new observation. Alert suppression uses its
  existing window; this is not arbitrary HTTP-request idempotency after response loss.
- A crash between DB commit and RAM-state publication can occur. Restart preserves
  alert history and starts fresh causal state; raw observations are not persisted.
- Existing SQLite busy timeout may block the event loop for about five seconds
  under a writer lock. Fault-mode latency and multi-worker processing are not
  guaranteed by normal-path benchmarks.
- Startup/storage health policy, browser behavior and independent threat quality
  are outside this task. Existing quality blockers remain.

Freeze the code, 16 regressions, unchanged model versions/demo outputs and scoped
metrics. **Next incomplete task: training/runtime feature parity diagnosis only**,
without training, thresholds, promotion or reserved-data access. It has not started.
Commit/push remains separately pending.

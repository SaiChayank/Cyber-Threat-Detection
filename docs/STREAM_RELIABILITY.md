# Streaming reliability: current semantics and historical checks

**Scoped follow-up, 19 October 2026:** [SQLite read recovery](SQLITE_READ_RECOVERY_20261019.md)
adds safe alert/telemetry/initial-SSE 503 responses and clean late-storage-fault SSE
closure/resume. Canonical 574 backend tests and typecheck/build/demo pass; 100/100
direct delivery p95 252.68 ms, excluding capture/proxy/browser. Original history,
detectors and models are preserved. This supersedes read-error handling and scoped
delivery evidence only; older benchmark/evaluation statements below remain dated.

Audited **2 October 2026**. The 29 September results below are a historical
implementation record, not the latest benchmark, capture regression, test suite or
deployed-model evaluation. The old classifier/capture runtime hashes differ from
current source. No reliability measurement was rerun in this documentation task.
See [report currency](STREAMING_VALIDATION.md) and
[source-matching performance](PERFORMANCE_VALIDATION.md).

## Current runtime contract

- Global packet/byte rates retain all counts in bounded one-second buckets;
  the old 4,096-event rate cap no longer applies. Ten-second rates retain part of
  the oldest bucket, with less than one second of overhang disclosed in evidence.
- Global entropy weights events with a 4,096-identity cap; target TCP/UDP entropy
  weights packets with a 256-identity cap and marked overflow lower bounds.
  At most 512 TCP and512 UDP target states are retained; target eviction can shorten
  history and does not have a separate target-eviction telemetry counter.
- TCP SYN detection requires known initial-SYN packet counts. Raw SYN-without-ACK
  contributes one, SYN+ACK contributes zero. Aggregate cumulative flags alone do
  not establish a fraction. Destination rate>=1,000/s and SYN share>=0.70 are
  required, so high established-TCP rate alone cannot trigger this path.
- UDP requires destination rate>=1,000/s and reports concentration/size evidence;
  legitimate bulk traffic can match. Reflection/amplification cannot be proven.
- Exfil rule/evidence use source-specific one-second forward-byte buckets over
  60 seconds, independently of the 512-event history cap. The classifier retains
  its historical bounded source-byte input. Missing reverse remains null;
  explicitly observed zero reverse also has no finite ratio but availability=true.
- Recon dedup is source/class scoped; target SYN/UDP DDOS dedup is destination/class
  scoped. Other classes retain source/destination/class scope. Suppression lasts
  30 event-time seconds; it never establishes a scenario-level negative label.
- API persists alerts before SSE sequence delivery. Database-backed resume and
  replay error/stop/upload/restart behavior have separate scoped validation reports.
  No message broker, WebSocket path or external database is introduced.

Latest saved source-matching runs on 1 October: core 20,000 events/1,170 commits,
5,649.91 metadata events/s, p50 0.0971 ms, p95 0.8416 ms; direct loopback API-to-SSE
100/100 matching records, p50 129.06 ms, p95 240.27 ms, p99 251.66 ms. Core excludes
capture/HTTP/SSE/browser; delivery excludes capture/Next.js/browser. Gates pass
within those scopes, not raw-capture-to-browser capacity or detection accuracy.

## Historical 29 September implementation record

This completes the first implementation task in the
[completion plan](COMPLETION_PLAN.md). It corrects stream accounting and measures
alert delivery. It does not complete public-data detection validation.

## Reproduced failure and fix

The previous global window stored at most 4,096 events and divided the retained
packet count by ten seconds. With one packet per event, its rate could not exceed
409.6 packets/sec. An isolated 12,000-packet stream within six seconds reported
409.6/sec instead of the intended fixed-window 1,200/sec. The 1,000/sec DDoS rule
could not fire, even though aggregated synthetic flow summaries could trigger it.

`features/rate_window.py` now maintains packet/byte totals in time buckets rather
than a capacity-limited raw-event buffer. At most eleven one-second buckets are
retained. The partial oldest second is included, so rates can include up to one
extra second of observations; evidence discloses the 10-second denominator and
1,000 ms resolution. This is an explicitly approximate rolling window.

Source entropy uses event counts, preserving the original feature definition.
At most 4,096 source identities plus one overflow group are retained globally.
Overflow identities remain grouped until their observations expire, avoiding a
false increase in entropy when capacity becomes available. Overflow produces a
lower-bound entropy and `source_entropy_partial=true`; packet and byte totals are
never discarded. Late events are rejected before aggregate state changes.

The fitted 20-feature Gaussian NB artifact and disabled DGA candidate are unchanged.
`python -m ml.train --evaluate-only` verifies the frozen classifier against the
current extractor without replacing either model. Synthetic validation/test macro
F1 remains 0.98948/0.99025. This is historical lab regression evidence, not current
malware accuracy or hybrid alert accuracy.

## Functional checks

At that revision **89 backend tests passed**, including eight rate-window regressions:

- A 12,000-packet stream triggers the DDoS rule at packet 10,000, before completion.
- Aggregated flow summaries and equivalent packet observations retain equal totals.
- Rates and entropy match a separately calculated time-bucket reference.
- Expiry, long gaps, overflow capacity, sticky overflow grouping and late events
  preserve the stated bounds and evidence semantics.

The final production build and TypeScript compilation pass. The restarted Monitor
connects, loads its original **130 saved alerts**, and displays the updated benchmark
without browser console errors. No new layout or responsive behavior is claimed:
the frontend components were not changed in this task.

## Throughput and delivery measurements

| Measurement | Result | Declared target and scope |
| --- | ---: | --- |
| Core + SQLite throughput | 3,027 metadata events/sec | >=2,000/sec; 20,000-event synthetic mixed workload |
| Core + SQLite p95 | 1.08 ms | <50 ms; excludes HTTP, capture and rendering |
| API acceptance p95 | 6.21 ms | Loopback request/inference/SQLite response, measured separately |
| API-to-SSE p95 | 250.09 ms | <1,000 ms; 100 simulated flow summaries, one subscriber |
| API-to-SSE maximum | 256.10 ms | Same isolated loopback run |

`benchmarks/delivery.py` starts an owned API bound to 127.0.0.1 with a temporary
SQLite database, sends simulated metadata, and correlates every SSE alert's sequence
and ID with its ingest response and saved history. All **100/100** expected alerts
arrived. A separate reconnect verifies `Last-Event-ID` resumes at the next alert.
The owned process and temporary database are cleaned up after the check.

This measures direct API ingestion, persistence and SSE receipt; it excludes the
Next.js proxy, browser rendering, raw capture and concurrent subscribers. Historical
traffic timestamps are never subtracted from the wall clock to invent latency.
The live analyst database is untouched by tests and benchmarks.

The benchmark filenames were subsequently overwritten by the1 October measured
runs; their current values are not the historical table above. The retained
`ml/runtime_evaluation.json` remains a29 September classifier-only report.

## Refreshed public-capture regression

All fourteen existing captures were replayed again: **609,583 parsed IP packets**.
The isolated original-domain comparison remains TP 478 / FN 5,518 / FP 0 / TN 1,000:
7.97% DGA recall on those previously inspected strings. The active guard therefore
remains weak; the broader lexical candidate is still disabled.

The two benign-reference captures emit 96 deduplicated alerts: 55 DDoS, 25 DGA,
13 C2 and three reconnaissance. These are false-positive candidates, not per-flow
FPR. Their earlier guard run emitted 97 alerts. A one-alert difference is not proof
of improved detection. There are still no tunnelling alerts on the unlabelled mixed
captures. No capture is relabelled just to produce a successful result.

`ml/streaming_validation.json` contains that revision's counts and source hashes,
including the new helper. Capture-processing timings are local unpaced observations
and are separate from the core/SSE benchmark targets.

## Reproduce

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m ml.train --evaluate-only
.venv/Scripts/python.exe -m datasets.validate_streaming
.venv/Scripts/python.exe -m benchmarks.run --events 20000
.venv/Scripts/python.exe -m benchmarks.delivery --events 100
npm run build
npm start
```

Run performance measurements without other CPU-heavy jobs. Existing public raw
files are needed for capture validation, but not for backend tests, model regression,
core/delivery benchmarking or application startup. No monitored host is queried,
no payload is decrypted and no network attack is transmitted.

## Event recovery follow-up — 3 October 2026

[Event recovery validation](EVENT_RECOVERY_VALIDATION.md) proves rollback of failed
feature/inference/alert/persistence operations, atomic event alert batches and
retry-to-SSE/restart behavior. The full 268-test suite passes. Core+SQLite p95 is
0.9228 ms at 4,072.43 events/s; direct API-to-SSE p95 is 248.92 ms for 100/100 alerts.
These separately saved results supersede earlier source-match claims for changed
runtime files; historical reports retain their dates. Retry ordering, busy timeout
and in-memory restart limitations are disclosed. Model quality is unchanged.

The historical “phase2 next” recommendation is superseded by the
[completion plan](COMPLETION_PLAN.md). DGA final data, tunnel labels and other
quality gaps remain unresolved. Passing reliability checks never authorizes
activation of failed or unevaluated candidates.

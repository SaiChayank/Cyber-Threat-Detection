# API/SSE cursor overflow correction

19 October 2026 IST; baseline `e1b14bf`. **Scoped DoD: PASS.** Independent T50
input-validation precursor, not final hardening or detector-quality acceptance.

Inspected alert/SSE routes, signed SQLite sequence storage, existing persistence/
resume/recovery tests and frozen source contracts. The bounded protocol precedes
the reproduction in `verification/cursor-validation-20261019/`.

## Root cause and change

Query cursors had only a lower bound; the Last-Event-ID header was converted to an
unbounded Python integer. A value above SQLite's signed 64-bit range reached the
store. Actual isolated-database reproduction recorded `OverflowError: Python int
too large to convert to SQLite INTEGER`: alerts returned 500, while SSE could send
200 headers before its generator failed. Six rejection regressions failed first.

`backend/application.py` now bounds both query cursors to `2**63 - 1` and rejects
oversized numeric header cursors with HTTP 422 before database/stream access.
Valid cursor precedence and the existing nonnumeric/negative-header fallback are
unchanged. No database schema, detector, feature, rule, model or dependency changed.
`tests/test_alert_cursor_validation.py` adds eight cases covering rejection before
storage, the valid signed boundary and real-stream boundary/fallback behavior.

## Results and provenance

- Before → after: invalid alerts **500 → 422**; invalid SSE query/header **200
  then generator failure → 422 before stream startup**. No ordinary alert/body,
  sequence, history or valid resume behavior changes.
- Initial focused run: six expected failures. After fix: **13 targeted passes**
  including existing SQLite/reconnect tests, 10.83 seconds.
- Initial full suite: **547 passed/two failures**, both caused by the correctly
  invalidated API source pin in the frozen demo manifest. Log retained explicitly.
- Before refreshing that pin, all **nine complete expected traces** were compared
  unchanged, including counts, classes, evidence, positions and timing. Exactly
  one provenance hash in `data/demo/manifest.json`, and its manifest sidecar, were
  updated. No fixture/expected result/model/gate changed; the old manifest remains
  referenced by Git `e1b14bf:data/demo/manifest.json`. Receipt lists old/new hashes.
- Focused demo/cursor rerun: **23 passed**, 20.65 seconds. Final full backend:
  **549 passed**, one existing Starlette/httpx warning, **131.50 seconds**.
- Root TypeScript and production build pass. No frontend source changed; no new
  browser or responsive audit is claimed by this package.
- Demo preflight passes all nine fixtures; disabled candidates remain disabled.
- Fresh loopback API/persistence/SSE benchmark: **100/100** exact records,
  p50 **155.4742 ms**, p95 **246.0066 ms**, p99 **254.1516 ms**; <1,000 ms gate
  passes. Durable state and resume verified. Excludes capture, Next proxy,
  browser rendering and concurrent subscribers; not sustained capacity evidence.
  The earlier clean-checkout p95 was 245.8072 ms, a separate run/environment;
  no controlled performance improvement claim. Core processing was not changed
  or remeasured; its historical result stays historical.

Protected-state check permits only the two documented demo provenance files.
The other **128 protected files**, including original analyst DB/WAL/SHM, models,
datasets/manifests and research contracts, are unchanged. New logs/receipts are
dated; historical reports and benchmark files were not overwritten. Both initial
failure and corrected runs are retained. No reserved observations or training.

## Freeze, limitations and next

Freeze the API correction, eight regressions, provenance receipt and measured
results. Confidence/accuracy, source qualification and release blockers remain
unchanged. A well-formed future cursor still waits for later records by design;
existing malformed-header compatibility is intentionally retained. This is not
authentication, a broker, global rate limiting or final security clearance.

Next independent package: reproduce upload temporary-storage allocation/write
failures in disposable tests; correct only a demonstrated upload-error handling
defect, preserving cleanup/history and all detector contracts. T21 UDP remains
blocked on its producer runbook and independent service/run labels.

# SQLite history-read error recovery

19 October 2026 IST; baseline `47a09f6`. **Scoped Definition of Done: PASS.**
The source-data/observability blockers and final release gates remain unresolved.

## Inspection and root cause

Inspected the saved read-error diagnosis, AlertStore, alert/telemetry/SSE handlers,
cursor/restart/resume/event-recovery tests, Monitor's existing API error and native
EventSource reconnect handling, frozen demo provenance and execution plans.
SQLite exceptions escaped alert and telemetry reads. SSE did its first read inside
the generator, after successful response headers. No detector defect was involved.

## Changes

- `backend/application.py`: catch only `sqlite3.Error` at history-read boundaries,
  log server-side and return actionable generic JSON 503. Prefetch the first SSE
  page before returning streaming headers. A later SQLite read failure closes the
  stream, allowing sequence-based reconnection to durable history. Unrelated
  programming errors are not translated into storage errors.
- `tests/test_sqlite_read_recovery.py`: 17 cases covering three routes and three
  SQLite exception classes, real closed connections, programming-error separation,
  unchanged history/pagination/filtering, and late-failure resume with both an empty
  and populated initial stream.
- `data/demo/manifest.json` and `.sha256`: only the API source pin/checksum changed,
  after all nine fixture hashes and complete frozen expected traces matched. The
  prior manifest remains referenced by Git; no expected result was rewritten.
- This report, streaming reliability and completion/progress pointers, plus the
  dated protocol, controllers, logs, comparison receipts and hashes under
  `verification/sqlite-read-recovery-20261019/`.

No persistence schema, database implementation, frontend component, dependency,
detector, model, threshold, research gate or reserved dataset changed.

## Tests and measured before/after

The new regressions first produced **15 failures / 2 passes** on the unchanged API
using global Python; that red log is retained. In particular, alert/telemetry reads
returned 500 and initial SSE returned 200 before failing. After repair, all three
initial reads return **503** with no client-visible SQLite/path details; late SSE
SQLite failure ends cleanly instead of propagating an iterator error.

Canonical verification uses the existing project `.venv` (Python 3.13.5):

- **46 targeted tests pass**, including real loopback 110-record restart/resume.
- **574 full backend tests pass**, versus the previous 557; one existing
  Starlette/httpx deprecation warning, no skips. Full pytest time: 130.84 seconds.
- TypeScript compiler and production build pass with the normal environment.
- All **nine** frozen demo scenarios pass, with unchanged evidence and timing.
- A separate real HTTP/SSE fault controller receives an initial record, forces a
  read failure/clean EOF, persists two records while disconnected, verifies initial
  503 on all three routes, removes the fault and resumes exactly those two records.
  Three durable records remain identical after the owned API process exits;
  zero duplicate records. Fault injection exists only in the verification process.

An initial full run inadvertently used global Python: **566 passes / one skipped
module**, because optional `stream_inflate` tooling was absent and its eight tests
were not collected. That run and its delivery/fault results are preserved with
`global-python-` prefixes as supplementary evidence. The `.venv` rerun above closes
that environment coverage gap; no package was installed and no skip was removed.

Fresh canonical direct loopback delivery: **100 accepted / 100 persisted / 100
delivered**, p50 **161.98 ms**, p95 **252.68 ms**, p99 **259.85 ms**. The p95 gate
of <1000 ms passes. Previous comparable package p95 was 244.69 ms; the small change
is not attributed to code or presented as a capacity improvement. Elapsed serial
batch time is 0.7748 seconds, not sustained throughput. The JSON records exact
values, hardware, Python and source hashes. Scope includes API ingestion,
inference, SQLite and direct SSE; excludes raw capture, Next proxy, browser rendering
and concurrent subscribers. The separate core benchmark was not rerun/relabelled.

## Integrity, freeze and limitations

Of 130 protected files, **128 are byte-identical**; only the two documented demo
provenance files changed. Original analyst SQLite/WAL/SHM, datasets, models,
research contracts and acceptance gates remain unchanged. The deployed model SHA256
remains `4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
Failed DGA/DNS candidates remain disabled. No training or reserved scoring ran.

Freeze this behavior, 17 regressions, measured results, provenance receipt and known
limitations in the package `freeze.json`. No further refactor/optimization is
justified without a new defect. Physical disk corruption/repair, multi-subscriber
capacity and browser rendering were not tested here. Closed storage is reported,
not automatically reopened or replaced. `/api/health` remains process liveness,
not database readiness. A client must retain its last delivered sequence to resume;
this does not promise globally exactly-once transport.

## Reproduce and next task

From the repository root:

```powershell
.venv/Scripts/python.exe -B docs/verification/sqlite-read-recovery-20261019/run_checks.py targeted
.venv/Scripts/python.exe -B docs/verification/sqlite-read-recovery-20261019/run_checks.py backend
.venv/Scripts/python.exe -B docs/verification/sqlite-read-recovery-20261019/run_checks.py frontend
.venv/Scripts/python.exe -B docs/verification/sqlite-read-recovery-20261019/verify_loopback_faults.py
.venv/Scripts/python.exe -B docs/verification/sqlite-read-recovery-20261019/run_checks.py delivery
```

Use a new output directory when capturing a later run; do not overwrite this frozen
evidence. The one-shot provenance refresh controller records this correction and
intentionally refuses a second refresh of the changed manifest.

Exactly next: verify the existing Monitor through its Next proxy shows database-read
503/reconnect state and recovers its persisted alerts without duplicates, using an
isolated test database at desktop/tablet/mobile widths. This is a scoped integration
check, not a redesign. Data-dependent detector tasks stay blocked until their frozen
source/label/coverage prerequisites pass. No promotion, outgoing request or release
READY is authorized by this reliability pass.

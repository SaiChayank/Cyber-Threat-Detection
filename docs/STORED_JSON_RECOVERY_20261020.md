# Malformed saved-alert JSON read recovery

20 October 2026 IST; baseline `517d685`. **Scoped DoD PASS.** No data repair,
detector/model change, training, reserved access, schema migration or release READY.

Inspected AlertStore deserialization, API read-error/SSE handling, existing SQLite
and recovery tests, alert schema and preservation inventory. A syntactically bad
JSON body, scalar/list/null or invalid UTF-8 BLOB escaped as a JSON/TypeError rather
than a sqlite3.Error. This returned 500 for alert/initial-stream reads and raised
out of an active stream instead of using the existing controlled EOF/resume path.

## Minimal fix and regressions

Only `persistence/store.py` runtime behavior changes. List deserialization requires
a JSON object and wraps ValueError/TypeError in a generic sqlite3.DatabaseError.
The existing API already converts that to a safe storage 503 before SSE headers
or clean closure after a stream starts. No row is discarded, replaced or rewritten;
an affected read batch returns no partial results. Writers, transactions, schema,
sequence assignment, filtering and normal record payloads remain unchanged.

`tests/test_stored_json_recovery.py` adds **23 red-first regressions**: seven stored
body forms, both alert and initial-SSE APIs for each, and late stream corruption
with/without an initial alert. They verify unchanged SQL rows, safe 503/no private
sentinel, a valid bounded page, exact history restoration and next-sequence resume
without duplicates after the test-controlled body is restored.

## Verification and scoped measurements

- Before correction: **23 failed**. After: **61 targeted** persistence/recovery
  tests pass in 23.03 seconds.
- Full backend: **616 passed**, zero skips, one existing Starlette/httpx warning,
  152.60 seconds. This is the preceding 593 plus the 23 new cases.
- TypeScript and normal production build pass. All nine complete frozen demo
  traces still match; **no demo/model pin changed**. An initial diagnostic helper
  assumed the demo pinned persistence/store.py and stopped with KeyError before
  any writes. Normal preflight verifies the unchanged actual manifest successfully.
- Fresh declared core: 20,000 events, 1,170 commits, **5.055941 seconds**,
  **3,955.74 metadata events/sec**, processing + SQLite p50 **0.1704 ms**,
  p95 **0.9790 ms**. Targets >=2,000/sec and <50 ms pass.
- Direct API -> SQLite -> SSE: **100/100** exact accepted/persisted/delivered
  records, p50 **156.75 ms**, p95 **249.29 ms**, p99 **258.56 ms**; durable reopening
  and cursor resume pass. Target <1,000 ms passes.
- Prior scoped core was 3,797.43/sec/p95 1.0117 ms; delivery p95 245.94 ms.
  Differences are run variation, not a claimed optimization. Neither benchmark
  measures raw-capture-to-browser throughput; core excludes HTTP/SSE/rendering,
  delivery excludes capture/Next/browser/concurrent subscribers.
- All **130 current protected files** match, including original DB/WAL/SHM, raw
  data, model/gate/demo artifacts. Runtime/store, benchmark and model source hashes
  in the new measurements match current bytes. Canonical latest JSON pointers now
  contain these actually rerun reports; previous canonical bytes are preserved
  exactly as base64/SHA in this package. New report line endings normalize to LF.

[Protocol, red/green/full tests, build, hashes and benchmark evidence](verification/stored-json-recovery-20261020/)
freeze the correction. No frontend source or unrelated detector refactoring.

## Limits and next task

Unreadable records remain present and the affected read stays unavailable until
storage is recovered. No automatic repair, deletion or fabricated replacement is
introduced. This checks JSON readability/object shape, not every AlertEvent field,
identity consistency or physical-disk corruption. Health liveness and aggregate
counts can remain available when an individual JSON body is unreadable.

Freeze passing behavior/tests/results/known limits. **Exactly next:** review the
public provenance/alias identities of the three already shortlisted DGA families
against exposed source inventories. Metadata/documents only; no domain rows,
training, scoring, new partition assignment or gate relaxation.

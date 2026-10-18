# Current-baseline restart verification completed

18 October 2026 IST. **Restart task Definition of Done: PASS.** Completes the
interrupted restart portion of [the clean-checkout checkpoint](CLEAN_CHECKOUT_20261018.md).
The earlier PARTIAL record remains historical; this supplement supplies the missing
measurement without rewriting its frozen evidence. Final T60 and release remain
blocked by unresolved detector quality, not by this restart check.

## Inspected and finding

Inspected the completion/remaining-work plans, prior clean-checkout protocol,
retained 30-record snapshot, launcher/environment, SQLite store, API alert/telemetry
and SSE routes, Monitor hook/services, and existing restart/resume tests. Preregistered
[this bounded protocol](verification/restart-completion-20261018/PROTOCOL.md) before
startup. Source baseline `49855bc`; isolated application commit `4e92b3b`.

The prior gap was an interrupted verification step, not a demonstrated application
failure. Its unused helper expected the first 15 records, while the preserved
database correctly contained 30 after a later replay. The new evidence-local
controller pins and compares the actual 30-record snapshot. It does not clear
history, fabricate expected records or modify the frozen historical helper.

## Executed results

- Confirmed retained clone revision, original snapshot/hash and full SQLite
  record equality before startup. Runtime source/model identities match.
- Started the existing production launcher twice, stopping only each owned
  process tree between/after checks. Both lifetimes recover **all 30 records**:
  alert IDs, sequences, order, class, evidence and every other stored field match.
- Seven-row pagination reconstructs the exact history; newest ordering and all
  seven threat filters agree with SQLite. Class summaries match recorded rows.
- Fresh runtime has **zero processed events**, idle replay and no replay error.
  Historical alerts remain present, correctly distinct from current runtime state.
- Proxy SSE with `Last-Event-ID: 15` delivers **exactly the remaining 15 records**,
  matching persisted bodies and sequence event IDs. Zero duplicate records; read
  through the next heartbeat to check the whole available backlog.
- Monitor opened/reloaded against both lifetimes: connected stream, 30 matching/
  loaded records, idle runtime and zero new events. Browser console captured no
  warnings/errors. An initial exact-text locator did not match the combined
  connection label; the actual AX state confirmed recovery. This was a verification
  selector issue, not an application connection failure.
- Existing tests, run in the fresh checkout's own Python environment:
  `python -m pytest tests/test_sqlite_restart.py tests/test_sse_resume.py -q -p no:cacheprovider`:
  **5 passed, one existing Starlette/httpx deprecation warning, 7.42 seconds**.
  Covers process restart/sequence continuation, pagination/filtering, duplicates,
  unavailable/corrupt database and SSE reconnect/resume using disposable test data.
- **130 protected original files**, including analyst database/WAL/SHM, models
  and frozen research contracts, remain byte-identical. Retained clone history
  stays 30 records. No ingest, replay, upload or training request was made.

## Change scope and freeze

Added only the structured [execution plan](COMPLETION_EXECUTION_20261018.md),
evidence-local restart controller, protocol/results/browser snapshots, this report
and dated plan/README links. No new application tests were necessary because no
application bug was fixed; existing meaningful regressions were reused.

No shared application code/dependency changed, so the full suite/typecheck/build
were not needlessly repeated. The separate current-baseline runs remain **533
passes in the developer environment**, and **531 passes/three optional skips in
the clean base environment**, with TypeScript/build passing. Those are distinct
earlier runs, not test counts measured by this task. No detection accuracy or
performance metric was rerun or changed here. All acceptance gates remain frozen.

Freeze the controller, five-test result, exact record comparison, screenshots and
limitations. This proves two local Windows production lifetimes of the retained
checkout; it is not a new clean installation, Linux test, public-data evaluation,
production security clearance or final-release acceptance.

## Exact next task

**T21: qualify one independently labelled flood/benign UDP pair on the same service
with overlapping load.** Obtain/verify producer runbook, independent labels and
original timestamps before packet values. Current source screen remains blocked;
no justified detector experiment is eligible. Do not lower gates or infer malicious
intent from a rate/source-diversity collision. Other source tracks may proceed
only when their own frozen prerequisites can be satisfied; no automatic promotion.

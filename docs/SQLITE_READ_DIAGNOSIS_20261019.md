# Runtime history-read failure checkpoint

19 October 2026 IST; baseline `09e97ff`. **Diagnostic DoD: PASS; repair NOT STARTED.**
This records the next bounded hardening task before the account session allowance
is exhausted. No partially tested production change is left in the repository.

Inspected AlertStore list/summary, alert/telemetry/SSE routes and Monitor's existing
API-error/reconnect handling. The protocol and reproducible controller are in
`verification/sqlite-read-diagnosis-20261019/`. Only disposable SQLite and a single
existing controlled alert fixture were used. No original database or source data
was opened by the application; protected original files were compared as bytes.

## Measured finding

Injected `sqlite3.OperationalError` in the current read operations:

- `/api/alerts`: **500**, unstructured generic response.
- `/api/telemetry`: **500**, unstructured generic response.
- Initial `/api/stream`: **200** headers followed by generator failure.

For every case, removing the fault restores the exact earlier fixture alert.
No history loss was observed. `/api/health` remains a shallow process-liveness
check, not database readiness; its 200 is not evidence that reads succeeded.
This is controlled exception injection, not physical storage-corruption testing.

Root cause: SQLite read exceptions are not translated at these existing API
boundaries; SSE first reads inside its generator after response headers start.
This resembles the now-fixed cursor overflow symptom but has a separate runtime
storage cause. Valid cursor/storage behavior was not changed by this diagnosis.

## Smallest next repair

Use narrow SQLite error handling at the existing read boundaries: safe actionable
503 for alert/telemetry read failures, and an initial SSE read failure reported
before successful streaming headers. If storage fails after streaming starts,
terminate/reconnect deterministically and resume from persisted sequence without
dropping or duplicating analyst records. Do not replace/recreate the database,
add a broker, hide unrelated programming errors or change the alert schema.

Add exact regressions for those faults and recovery, valid pagination/filtering,
mid-stream failure/resume and preserved records. Then full backend, TypeScript/
build, demo trace equality/provenance and source-matching delivery measurement.
Any affected demo source pin may change only after its frozen expected traces
are proved unchanged, following the previous two correction receipts.

## Scope and freeze

Only diagnosis controller/protocol/results, this report and plan/progress pointers
were added. No application code/test/model, database, artifact or gate changed.
No new unit-test count/full-suite/build/performance result is claimed here; the
preceding source package still has 557 passes, TypeScript/build and scoped delivery
evidence. All **130 protected original hashes** remain unchanged.

Freeze the three observed responses, recovery result and limitation. This is a
P1 read-error handling gap to repair in the next work period, not accepted failure
recovery. Required P0 detector data/observability blockers remain unchanged; no
training, reserved evaluation, failed-candidate activation or release READY.

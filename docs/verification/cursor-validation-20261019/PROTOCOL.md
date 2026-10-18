# Scoped API/SSE cursor validation

19 October 2026 IST; baseline `e1b14bf`. Independent T50 precursor, not final
hardening completion. Inspect existing alert pagination, SSE resume, SQLite signed
sequence storage, failure tests and frozen research source bindings before edits.

Reproduce oversized integer cursors using disposable TestClient databases. An
invalid request must return validation error before database/stream access, rather
than server failure or successful SSE headers followed by disconnect. Keep valid
sequence semantics, max(query, Last-Event-ID) resume precedence, alert bodies,
history, existing malformed-header compatibility and detector behavior unchanged.

If reproduced, limit the fix to existing API request validation and exact
regressions. No database migration or new service/dependency. Test the signed
SQLite upper boundary, overflow query/header paths, rejected-access avoidance,
normal resume and benign malformed-header fallback. Run targeted tests first,
then full backend and frontend typecheck/build because shared API behavior changes.
Verify demo/model/research contract identities and original analyst DB/WAL/SHM.
Record scoped before/after evidence; no detector evaluation, reserved data, training
or promotion. Refresh performance only if source relevance/measurement justifies it.

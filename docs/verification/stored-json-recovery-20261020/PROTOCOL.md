# Malformed stored-alert JSON recovery

20 October 2026 IST; baseline `517d685`. Reproduce before changing code.
Scope: AlertStore list deserialization only, using disposable SQLite fixtures.
Current API already converts sqlite3.Error into safe read 503 and closes an
already-started SSE stream. Test whether corrupt JSON/non-object/BLOB bodies
incorrectly escape that boundary. Preserve exact rows; no automatic repair,
discard, migration, history replacement or new database dependency.

Acceptance: invalid JSON/non-object/invalid UTF-8 records raise a storage-read
failure with no partial batch; alert API/initial SSE return existing safe 503,
private stored text absent; late SSE ends and resumes the same next sequence
after restoring the controlled fixture; original records and ordering survive.
Normal JSON objects remain unchanged. This is not full schema/corruption repair.
Add regressions for every demonstrated case, run targeted then full backend and
frontend build, frozen demo trace and delivery checks because shared persistence
behavior changes. No detector/model/gate or dataset values. Commit only on pass.

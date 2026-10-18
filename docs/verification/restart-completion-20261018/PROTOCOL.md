# Complete the interrupted current-baseline restart check

18 October 2026 IST; source commit `49855bc`, isolated application commit `4e92b3b`.
Before service startup, compare the saved 30-record history to the isolated SQLite
database read-only and pin its snapshot hash. Refuse missing/different history,
changed runtime/model source, occupied ports or a mismatched clone commit.

Start the README production launcher with that checkout's own environment,
dependencies, build and existing database. No ingest/replay/upload/write request.
Verify every stored record through the proxy API, ordering, seven-row pagination,
threat filtering, newest ordering, summary and fresh idle/zero-event telemetry.
Resume SSE from sequence 15 and require exact remaining records and event IDs,
without duplicate delivery. Check Monitor recovers 30 historical records with a
connected stream. Stop only owned services, start again and repeat exact record
and runtime-reset comparisons. Finally stop test services and retain the database.

Use existing SQLite/SSE regression tests with disposable databases. No runtime
change unless a measured defect needs a minimal fix and regression. Preserve all
original project database/WAL/SHM/model/data/contract hashes and frozen reports.
No new model, training, reserved data, active network observation or messaging.

DoD: exact 30-record continuity across two new production lifetimes, deterministic
SSE catch-up and Monitor reload, targeted tests pass, protected originals unchanged.
Report this as completing the earlier current-baseline rehearsal, not final T60,
release READY, a fresh full-suite/build rerun or new detection-quality measurement.

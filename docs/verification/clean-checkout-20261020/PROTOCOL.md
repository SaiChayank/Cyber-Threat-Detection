# Current-runtime fresh-checkout rehearsal

20 October 2026, Asia/Calcutta. Source `f380837`. No detector/data qualification
or release acceptance is implied. The preceding runtime fixes are now committed;
this task checks their documented installation/demo path in a new environment.

Clone only committed local Git state with no local hard links, Windows
core.autocrlf=true checkout, no copied venv/node_modules/.env/raw data/history.
Use system prerequisites allowed by README, normal package-registry caches only.
Install with npm install, then npm run dev to bootstrap a genuinely new Python
venv using requirements.txt. Only documented .env port/database settings change:
API 18420, website 13420, local data/alerts.sqlite3. Never reuse or stop unrelated
services. Preserve the new test database after the rehearsal.

Run README pip consistency/typecheck/full backend tests/demo preflight/production
build/start/offline replay/core and direct-delivery benchmark commands. Record
actual optional skips instead of installing unrelated research dependencies.
Verify seven bundled model hashes and frozen contracts without retraining.
Production Monitor must start empty, launch the 256-event ALL replay at 20x,
show incremental alerts, and finish with 15 alerts/seven classes. Compare full
proxy SSE, API and read-only SQLite records and retain the first alert's event
position before completion. Capture browser state/console/screenshot.

Stop only this task's owned process tree, restart production against its retained
history, verify exact IDs/order/evidence, idle telemetry and sequence resume, and
close only the owned tab/process. No deletion or reset of original/test history.

Record every setup failure/undocumented step. Fix setup/documentation only if an
actual defect appears; add regressions for any code defect. DoD: isolated setup,
base-suite passes with explained optional skips, types/build/demo/hash integrity,
actual incremental production delivery and restart continuity all pass. Core
>=2,000 metadata events/sec/p95<50ms and direct API-to-SSE p95<1,000ms keep their
existing scopes; no capture/browser throughput or accuracy claims. Original 130
protected files must match after execution. Freeze and commit the verified package;
no push, new model scoring, gate changes or activation.

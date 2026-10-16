# Dependency security triage — scope fixed before updates

16 October 2026, baseline `e2a34b9`. Target the two npm packages reproduced by a
fresh audit: Next.js 16.3.6 and transitive source-map-js 1.2.1. Assess all seven
advisory entries, not just the packages' aggregate high-severity labels.

Use publisher advisories/patches and npm registry metadata; distinguish installed
vulnerability from demonstrated application reachability. No live exploitation,
untrusted source-map upload, active network attack or detector experiment.

Minimal update: Next.js 16.3.8 with its required matching @next/env/SWC artifacts;
source-map-js 1.2.2 within parents' existing compatible range. Raise the frontend's
Next.js minimum patch. No major upgrades, new dependency, forced audit fix,
framework migration, overrides, unrelated package refresh or Python change.

Acceptance: fresh install from updated lock; dependency tree valid; npm audit
reports neither target and no remaining advisory; added regression checks fail
against the old dependency state and pass with the fix. Use bounded invalid-map
constructor cases, never trigger the old library's unbounded serialization loop.
Run packaging/security regressions, TypeScript, production build and full backend
regressions because the shared frontend runtime dependency changes. Smoke-test
landing, Monitor and API/replay/SSE through the production proxy with a disposable
SQLite database; check browser runtime errors. Do not alter existing user servers.

Record exact versions, before/after audit, install/delta/test/build evidence and
scope limitations. Preserve models, frozen protocols, datasets and analyst
history; verify original database/WAL/SHM hashes. No new quality/throughput claims
or refresh of frozen historical reports. Zero audit findings is point-in-time npm
advisory evidence, not a complete application/Python/OS security clearance.

Commit verified fixes under the user's standing instruction; do not push. Stop
after triage/remediation, with all unresolved detector/data blockers retained.

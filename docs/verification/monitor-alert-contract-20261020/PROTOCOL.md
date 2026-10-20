# Malformed alert recovery integration

20 October 2026. Baseline `7adccf4`. Diagnose the existing Monitor hook/schema/API
boundary, using development fixtures and disposable analyst storage only.
No model, detector, feature extraction, threshold, dataset role or frozen report
changes. No frontend redesign, framework or dependency is required.

Required behavior: invalid initial alert lists produce a visible recoverable
state; invalid SSE JSON/schema must not crash the page, erase valid history,
silently skip a repaired record, or have its error hidden by the next valid row.
After durable data is repaired, the existing polling/REST/SSE path must converge
to persisted records with no duplicates. Native reconnect behavior must remain.

First use an automated actual-hook test with existing TypeScript/Zod, controlled
API/EventSource boundaries and a minimal hook-state adapter. This is not a real
React renderer/browser or a throughput/accuracy benchmark. Save a failing
reproduction before any product edit. Change only the smallest proven failure,
add regressions, then run backend suite/typecheck/build and one real Monitor
fault/recovery observation through the existing proxy. Use CUA for actual browser
actions. Preserve all original history and 130 current pins. Commit only a
verified package; no push or private-source request.

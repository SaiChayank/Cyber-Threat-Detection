# Monitor refinement — 13 October 2026

Keep Univect's black/red/white identity, existing controls, API, SSE and alert
contract. Reuse Motion and current components; no added dependencies.

Add a bounded snapshot of loaded alerts to hold the visible investigation queue;
SSE ingestion and metrics continue. Resume shows the latest loaded records, with
the existing 200-record limit disclosed. Filter/export use displayed snapshot
while held. Add a real detection-engine filter and a visible filter reset.
Use restrained entrances/transitions with reduced-motion support.

Acceptance: existing browser regression passes, held rows stay stable while
new real API alerts persist/arrive, resume includes those records without
duplicates, engine filter/export agree, responsive 320/390/768/1440 layouts,
reduced-motion check, empty/error recovery and no unexpected browser errors.
TypeScript and production build pass. Run the full backend suite because this
stage includes end-to-end UI integration. Use a disposable database only.
Verify frozen models, raw inputs and detector code remain unchanged.

# SQLite read recovery acceptance freeze

19 October 2026 IST. Source baseline: `47a09f6`. No detector experiment.

Before modifying the API, freeze these criteria:

- Alert-list, telemetry-summary and initial SSE SQLite failures return structured
  HTTP 503 with an actionable retry message, without paths/SQLite exception text.
- Initial SSE failure occurs before successful streaming headers.
- A SQLite failure after streaming begins closes the iterator. Reconnection uses
  durable sequence/Last-Event-ID and delivers disconnected-period records exactly
  once when the analyst resumes from the last received sequence.
- Existing records, pagination, filters, cursor bounds and alert schema survive.
- Unexpected programming exceptions are not disguised as storage availability.
- Real closed-connection failures also fail safely; no database recreation.
- Only existing read boundaries change. No migrations, dependencies, model,
  thresholds, reserved data, capture parser or detector changes.

Use isolated temporary databases. Controlled exceptions test transient read faults,
not physical corruption recovery. Existing real-loopback SSE restart/backlog tests
remain required alongside direct iterator fault/resume tests.

Run new tests red first, targeted SQLite/SSE/cursor/event-recovery tests, all backend
tests, TypeScript and production build. Prove all nine frozen demo traces equal
before updating only API source provenance and its manifest checksum. Then rerun
100-alert loopback API/persistence/SSE delivery, p95 <1000ms. This excludes capture,
Next proxy and browser rendering. Preserve earlier failed logs and measurements.

Compare 130 protected original hashes before/after; only the two explicitly
documented demo-provenance files may change. Commit verified package, no push.

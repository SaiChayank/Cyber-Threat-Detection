# Monitor history-read outage integration freeze

19 October 2026 IST; source `135218f`. Use the current production frontend, Next
rewrite, FastAPI handlers, detection pipeline and SQLite. No product fault mode,
mock route, detector change or reserved data. Apply controlled SQLite read errors
only in an owned verification server with a disposable database.

Acceptance before testing:

- Seed two real API-generated fixture alerts. Monitor connects and displays their
  durable sequences/evidence. At 1440x1000, 768x1024 and 390x844, trigger a read
  outage after connection. Telemetry/list/initial-stream through the proxy return
  generic JSON 503; the active stream closes. UI shows Reconnecting, an actionable
  storage error, last-received-data wording and enabled Retry connection. Saved
  rows remain visible and replay/upload controls are unavailable.
- Commit two additional fixture alerts per outage through the real event API.
  While reads fail they must not appear as delivered. Remove the fault and exercise
  Retry connection/automatic reconnect. Expect exactly sequences 1..4, then 1..6,
  then 1..8, newest first without duplicates; error disappears and stream connects.
- Also reload once while storage reads fail: actionable initial error/empty state,
  followed by recovery of all eight records. Inspect one recovered record's detail
  and match its ID/flow/evidence against durable state.
- No page horizontal overflow. Table's own horizontal scrolling is allowed.
  Separate expected HTTP 503 resource diagnostics from unexpected runtime errors.
- Compare all 130 original protected hashes unchanged. No DB/schema/model/threshold
  or demo-provenance change. Preserve prior frozen results. Stop owned processes,
  reset viewport/close temporary tab and restore the default production build.

Freeze screenshots, rendered state, ASGI status/SSE sequence trace, exact record
comparisons, browser diagnostics, original hashes and limitations. This is controlled
failure recovery, not physical corruption repair, public-data quality, a latency
benchmark or a final release declaration. Commit verified package without pushing.
If a real defect appears, stop at that boundary and make only a tested correction.

# Replay error disclosure and recovery

20 October 2026 IST; baseline `47885f4`. **Scoped DoD PASS.** Required detector
quality/data gaps remain unresolved; this is not final release acceptance.

Inspected API replay/upload/telemetry handlers, public preset reader, PCAP header
diagnostics, Monitor error rendering, existing recovery tests, demo manifest and
130 protected-file pins. Raw `str(exc)` was copied into replay telemetry and
upload-header responses; cleanup errors also exposed their exception details.
These could include local filenames or internal source/persistence diagnostics.

## Correction

`backend/application.py` returns fixed actionable messages for unexpected replay,
storage, source and cleanup failures. Complete diagnostics/tracebacks stay in
backend logs. Only eight exact fixed PCAP validation strings are public, restricted
to ordinary ValueError instances. Arbitrary ValueError/Pydantic/runtime text is
not displayed. Expected invalid captures retain 422; unexpected header access or
validation faults now return retryable 503 instead of misclassifying storage as
bad input. No new parser, dependency, API field or UI component.

`tests/test_replay_error_safety.py` adds nine integration regressions: four source/
processing exception types, cleanup after completion/error/immediate stop, and two
header-read failures. All nine fail against the old behavior before correction.
They check private text stays out of responses, diagnostics remain logged, saved
alerts survive, applicable temporary files are removed and a new replay succeeds.
Two old replay tests now assert the intended safe text rather than leaked exception
details. Existing malformed/header/packet-length/truncation checks remain intact.

## Verification and measurements

- Nine pre-fix failures -> nine corrected cases pass; **34 targeted** replay/upload
  regressions pass in 9.44 seconds.
- Full `.venv` backend suite: **593 passed**, zero skips, one existing Starlette/httpx
  deprecation warning, 153.82 seconds. Previous source-matching full result was 574;
  ten intervening archive-tool tests plus these nine explain the increase.
- TypeScript and normal production build pass. No frontend runtime source changed.
- All nine complete synthetic demo alert/evidence/timing traces match the existing
  manifest before its API source pin was refreshed. Only that pin and manifest
  checksum change; no trace, fixture or model was regenerated.
- Real isolated direct API -> SQLite -> SSE: **100 accepted/persisted/delivered**
  exact records; p50 **156.50 ms**, p95 **243.91 ms**, p99 **253.71 ms**. Persistence
  after process shutdown and cursor resume pass. Previous scoped p95 was 252.68 ms;
  the small difference is run variation, not an optimization claim. Target <1,000 ms
  passes. This excludes capture, Next.js proxy, rendering and concurrent subscribers.
- 128 of 130 protected originals are byte-identical. The two intentional changes
  are demo manifest/source-provenance checksum files. Original DB/WAL/SHM, raw data,
  model/failed artifacts, detector sources and all acceptance gates are unchanged.

[Evidence](verification/replay-error-safety-20261020/) includes red/green/full-suite,
typecheck/build, trace comparison, benchmark and preservation records. Reproduce
targeted/backend/frontend/delivery stages with its `run_checks.py`; historical
logs are frozen and should not be overwritten during another evidence run.

## Limits and next step

Safe error reporting does not repair unavailable storage or guarantee file removal
when the operating system denies deletion. Backend logs intentionally retain local
diagnostics; they are not an externally exposed endpoint. Browser display of this
new failure wording is the next independent integration check. No fresh core
throughput, public-data accuracy or production-security result is claimed.

Freeze this behavior, nine new cases, source pin, measured delivery and limitations.
**Exactly next:** verify actual Monitor replay failure wording, retained alert
history and successful retry through an isolated production proxy, including
desktop/tablet/mobile views. No redesign, detector tuning or new public data.

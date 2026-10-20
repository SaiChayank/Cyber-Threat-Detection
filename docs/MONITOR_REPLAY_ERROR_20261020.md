# Monitor replay-error and retry integration

20 October 2026 IST; source `843bd4a`. **Scoped DoD PASS.** No product source,
detector, model, dataset or acceptance gate changed. This is controlled functional
recovery, not malware accuracy, a benchmark or a final release declaration.

## Story and inspected boundary

Monitor BENIGN replay action -> production Next proxy -> real FastAPI source
iterator -> real detection/SQLite commit -> failed replay telemetry -> safe
Monitor message -> successful retry. Inspected controls, Monitor error rendering,
new API error helper and prior owned-server verification before testing.
The verification skill guided the browser/API/data/response checks; no hosting
or new dependency was introduced.

The test-only server consumes a filesystem marker to yield one established
synthetic alert event and then raise a private-sentinel RuntimeError. It otherwise
uses the unchanged source generator. No fake API route, product fault switch,
public capture, traffic generation, model training or reserved data.

## Observed results

- **Desktop 1440x1000:** two initial alerts -> three after failure. Safe replay
  error shown, private sentinel absent, Start replay enabled. Retry completes the
  original 32 BENIGN events; error disappears and all three alerts remain.
- **Tablet 768x1024:** three -> four persisted alerts, same safe failure and
  successful 32-event retry; four records retained.
- **Mobile 390x844:** four -> five persisted alerts, same failure/retry behavior;
  five records retained. Start/stop/upload layout remains usable.
- All six captured failure/recovery states have no page horizontal overflow.
  Browser console capture has **zero errors and zero warnings**. Stream stays
  connected; all six state captures contain the live connection indicator.
- Final API has exactly sequences 1..5 and the original first two complete records
  unchanged. Reopening SQLite after owned API shutdown matches all five records.
  Final replay state complete, error null, processed count32.
- Isolated production proxy build and restored normal production build both pass.
  All **130 current protected hashes** match before/after, including the preceding
  package's intentional demo-provenance refresh. No further pin update.

An earlier attempt timed out waiting for browser work during a user-turn
interruption. Its logs/initial state and successful build restoration are preserved
under `attempt-1-interrupted/`; it established no browser pass and is not concealed
as a successful attempt. The second attempt starts a new disposable database and
provides the actual accepted results.

## Files, testing and freeze

Only this report, current plan/progress pointers and
[dated integration evidence](verification/monitor-replay-error-20261020/) are added.
The evidence contains isolated server/runner, six state screenshots/JSON, console,
API/durability checks, build logs and original hashes. No application tests added
or rerun: the source-matching 593 backend / 34 targeted tests and typecheck already
passed in the preceding package. Two fresh production builds are recorded here.
No before/after detection or performance improvement is claimed.

Freeze the three responsive failure/retry cycles, preserved records, clean console,
builds, source identity and limitations. Owned services are stopped, temporary
viewport override reset, browser tab closed, default build restored. Original
services and analyst database are untouched.

**Remaining limits:** deterministic source-failure injection does not simulate
every filesystem or operating-system failure. The reported retention counts are
functional integration evidence only. Required public-data quality blockers remain.

**Exactly next:** inspect the installed backend runtime dependency closure against
current publisher advisories; triage reachability and make only demonstrated
necessary remediation. Preserve the frozen detector/artifact/gate behavior.

# Monitor malformed-alert recovery

Finalized 21 October 2026, Asia/Calcutta; work/evidence package began 20 October.
Baseline `7adccf4`. **Definition of Done: PASS.** This fixes a demonstrated
frontend recovery defect without changing any detector or persisted record.

## Inspected and root cause

Reviewed the Monitor hook, Zod alert schema, REST service, alert feed, backend
history/SSE path, stored-JSON recovery regressions and existing UI test tooling.
Read the installed Next.js client-boundary guide required by frontend/AGENTS.md.

Malformed initial REST history already produced a visible recoverable state.
For a malformed SSE record, however, the hook only displayed an error and
continued. A subsequent valid message cleared the error and advanced its cursor
beyond the rejected sequence. Repairing that earlier durable record did not
trigger REST reconciliation, leaving a silently incomplete live queue until reload.

The SQLite reader deliberately checks JSON/object readability rather than the
entire alert contract. A valid JSON object with a missing field can therefore
reach the browser through the actual API/SSE path. This task does not change that
backend contract or repair data automatically.

## Minimal change and regression coverage

Only `frontend/src/hooks/use-monitor.ts` changes product behavior. Invalid SSE
JSON/schema now closes that connection, marks history uninitialized/unavailable,
retains existing alerts and lets the existing poll reload validated REST history.
The warning clears only after history parses successfully. New connections resume
after the reconciled cursor. Identity guards ignore queued callbacks from obsolete
connections so they cannot clear errors or close a later healthy connection.
Normal valid-message handling, 200-record display limit, replay and detector logic
remain unchanged. No dependency, framework, service, database or route is added.

`tests/frontend/monitor-alert-recovery.test.cjs` adds three actual-hook tests using
the installed TypeScript compiler and Zod, controlled API/EventSource boundaries
and a minimal hook-state adapter. It does not claim to be a real React renderer
or browser. Cases cover invalid initial history, malformed SSE schema and invalid
SSE JSON. They also exercise durable backfill, retained queue, stale callbacks,
resumed cursor, duplicate suppression and later valid messages.

## Verification and metrics

- Before product change: **one passed, two failed**, reproducing the warning
  being hidden. After: **all three pass** with the expanded recovery assertions.
- Full backend: **616 passed**, one existing Starlette/httpx warning, 140.57s.
  TypeScript, production build and all **nine** complete frozen demo traces pass.
- Actual isolated loopback API/SSE -> existing Next proxy -> Monitor observation:
  starts with row 1; atomically publishes a missing-confidence row 2 plus valid
  row 3. The page shows a recoverable incompatible-history warning, retains row 1
  and leaves the live state. After only the disposable row 2 body is repaired,
  the page automatically displays **[3, 2, 1]**, connected and warning-free,
  without reload, missing record or duplicate. API and retained SQLite contents
  match the expected three test records. These are transport fault fixtures,
  not new detection/accuracy evidence.
- Browser console: **zero errors and warnings** in this case. Both owned servers
  and their temporary tab are stopped/closed, while the three-record test database
  is retained. No unrelated service or original analyst history was changed.
- Running dev briefly changed generated `next-env.d.ts` imports. A separate final
  production build passed and restored the original generated file; it has no diff.
- **All 130 current protected source files match**, including history, raw data,
  gates and artifacts. No model/feature/threshold/promotion state changed.

The first live fault helper mistakenly passed a dict to a dataclass-only append
method and stopped before any inserted row. The corrected test-only helper uses
an atomic SQL corruption fixture; no product writer was changed to accommodate
the test. This unsuccessful attempt is disclosed rather than presented as a
passing application test.

[Red/green commands, full tests/build, fault/API state, screenshots and integrity](verification/monitor-alert-contract-20261020/)
freeze this correction. Original task-local receipt bytes are preserved outside
Git under ignored `data/raw/monitor-alert-contract-originals-20261021/`; readable
tracked text normalizes to LF. The polling API log is stored losslessly as
`api.log.gz` with both hashes recorded, avoiding thousands of repetitive lines
in the source diff. Before/after recovery: **two failing contract
regressions -> zero**, and the repaired sequence returns automatically. No new
accuracy or performance benchmark is claimed; core/direct-delivery code is unchanged.

## Limitations and next task

The system reports invalid stored alerts; it does not fabricate or repair them.
Reconciliation uses the existing latest-200 display window; older records remain
in SQLite/API pagination. A damaged row blocks that affected history response
until storage is repaired. Browser proof is one desktop fault case; the prior
three-viewport checks remain separately scoped historical evidence.

Freeze this passing behavior, tests, source hashes, measured results and limits.
The preceding clean-checkout rehearsal predates this client correction; repeat
the final complete rehearsal after all accepted changes. **Exactly next:** the
public UFU Do53 source's actual archive-member/run inventory and native capture
format qualification, before packet values. This is a candidate benign-DNS lead,
not an approved role or permission to train/score. The completion plan records
all remaining independent quality blockers; do not weaken them or start another
model experiment without its prerequisites.

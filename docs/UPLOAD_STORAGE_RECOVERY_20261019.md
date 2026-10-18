# PCAP upload staging-storage recovery

19 October 2026 IST; baseline `5302020`. **Scoped DoD: PASS.** Narrow T50
reliability precursor; detector/data-quality blockers and final release unchanged.

Inspected upload staging/cleanup, replay ownership, parser boundary, existing
upload/replay/recovery tests and frozen demo provenance. The pre-change protocol
is in `verification/upload-storage-20261019/PROTOCOL.md`. Only generated classic
PCAP fixtures and disposable databases were used; no raw source/evaluation data.

## Reproduction and smallest fix

Controlled ENOSPC/EACCES fault injections at temporary-file allocation, write and
close/flush returned HTTP 500. Six rejection/recovery regressions failed first.
Allocation and context-manager close sat outside the cleanup/error guard; write
failures cleaned up but propagated without actionable structured feedback.

`backend/application.py` now covers temporary allocation, streaming writes and
context-manager close with one staging guard. If a path was created it is removed
before returning HTTP **503** with a generic storage-recovery message. Internal
exception detail stays in backend logs, not the response. HTTP 413 and cancellation/
client-disconnect exceptions retain their original semantics after cleanup.
Valid ingest, parser support, replay pacing, detection/evidence and persistence
contracts are unchanged. No model, feature, rule, dependency or schema change.

## Tests and measured results

`tests/test_upload_storage_failures.py` adds **eight cases**: six storage-fault
combinations and two interrupted-staging cases. They verify staged-file removal,
healthy API, preserved prior alerts and event/replay state, generic feedback and
successful next valid upload. Permission failures are injected in allocation/
write/close; deletion remains permitted in the test directory. No real disk was
filled and no system permissions were altered.

- Before → after: six controlled staging-failure paths **500 → 503**. Interrupted
  uploads continue to propagate their interruption; earlier history is preserved.
- Upload/replay/recovery targeted set: **41 passed**, existing warning, **15.50 s**.
- Full backend: **557 passed**, one existing Starlette/httpx deprecation warning,
  **138.00 s**. Root TypeScript and production build pass.
- Before refreshing the changed API demo provenance, all **nine frozen expected
  traces and fixture hashes** were verified unchanged. Only that API source pin
  and the demo manifest sidecar changed. Previous manifest is recoverable at
  `5302020:data/demo/manifest.json`; receipt records old/new identities.
  No scenario, expected alert, evidence, timing or model output was rewritten.
- Demo preflight then passes all nine fixtures with both candidates still disabled.
- Fresh direct loopback API → persistence → SSE: **100/100** whole-record matches,
  p50 **154.3319 ms**, p95 **244.6922 ms**, p99 **252.6540 ms**; <1,000 ms gate
  passes. Persistence/resume verified. The immediately prior separate run had
  p95 246.0066 ms; no controlled performance-improvement claim. Excludes upload,
  capture parsing, Next proxy/browser, concurrent subscribers and physical traffic.
- **128 protected files** remain unchanged, including original analyst DB/WAL/SHM,
  model artifacts, data/research contracts. The two deliberately changed protected
  files are the demo source-provenance manifest and its checksum only.

## Change scope, freeze and limits

Changed the existing API staging block, new exact regressions, dated reports and
demo source provenance. Reused the prior evidence command runner with a separate
output directory; no frozen old logs were overwritten. Initial six-test failure
evidence is retained. No core benchmark or detection-quality evaluation was rerun.
No frontend source changed; a new browser/responsive audit is not claimed here.

Freeze this correction, eight cases, results/provenance and limitations. Cleanup
cannot be guaranteed when the filesystem itself refuses deletion; this package
does not change permissions or claim storage repair. Parser/replay read failures
after staging remain under their existing error handling; no new capture format,
URL/archive handling, external service or mitigation was introduced.

Exact next independent task: bounded review of the outstanding DGA/C2/TLS producer
responses and DNS issue clarification for a newly qualified provenance bundle.
No outgoing messages, download/scoring/training or model activation follows
unless its existing frozen prerequisites are actually satisfied. UDP T21 remains
blocked on same-service independent runbook/labels and original timing.

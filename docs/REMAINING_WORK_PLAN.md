# Univect / PS26145 — remaining work to release

15 October 2026. Planning only; no new implementation or evaluation is authorized
by this document. Baseline commit: `8f2cf30`. This execution order supplements
`COMPLETION_PLAN.md`; it does not overwrite historical evidence or supersede the
governing screenshots, frozen protocols or acceptance gates. The prior approximate
75% estimate is not an acceptance measurement. Release remains NOT READY.

## Definition of complete

Deliver the required passive local prototype: read-only ingest, causal features,
actual rule/ML inference, all required threat categories, standardized incremental
evidence-bearing alerts, persistent history, working Monitor, measured throughput,
reproducible source/demo and truthful model/training/validation documentation.

All release BLOCKERs must be closed with source-matching evidence. A failed or
unassessed required detector does not become accepted through a successful UI demo,
wording change or a completion percentage. If a frozen gate cannot be achieved
with available observations/data, record the blocker and request an explicit scope
decision; never silently weaken a gate or remove an official threat requirement.
Production hosting, enterprise authentication/RBAC, a new database, new capture
formats, graph analytics and a frontend redesign are outside this completion plan.

## Keep these working foundations

- Existing FastAPI/SQLite/SSE/replay/upload and React/Next.js Monitor architecture.
- Atomic event persistence/recovery, sequence resume and preserved analyst history.
- Current passive parser boundary and missing-reverse-data semantics.
- Bundled hash-checked models, disabled experimental candidates and frozen gates.
- Existing deterministic demo pack, alert schema, evidence and qualified wording.
- Latest verification: 377-test full backend run before the six new DNS-contract
  tests; 70-test targeted DNS/recovery run including those six; TypeScript/build;
  32 interactive browser checks; 11 packaging/contract checks after Git attributes
  were extended. These are different runs, not a newly measured full-suite total.

Do not refactor a passed feature unless a later integration test exposes a defect.

## Execution rules for every work package

1. Inspect its listed implementation, source-matching reports and frozen protocol.
2. Declare exact scope, input roles, exposure history, gates and output before
   inspecting new evaluation values. Work on one detector/task at a time.
3. Make the smallest evidence-justified change. No new service/dependency without
   a demonstrated need; no labels/source identity as predictive shortcuts.
4. Add meaningful regressions for defects; run the smallest relevant checks first.
   Run full backend and frontend build when shared runtime behavior changes.
5. Freeze passing code/tests/artifacts/report/limits. If a candidate fails, leave
   it disabled, analyze FP/FN by family/scenario and recommend one next experiment;
   do not implement that experiment in the failure-analysis task.
6. Every task reports inspected evidence, finding, files, tests/results, scoped
   before/after metrics, limitations, DoD and exactly one next incomplete task.

No active probing, detector-generated handshakes, inline mitigation, return-path
dependency, payload decryption, reserved tuning or automatic model activation.
Use disposable test databases. Preserve original raw files and existing reports.
New external recipients/messages require direct user authorization. This plan is
not authorization to post additional requests or watch email automatically.

## Phase 1 — finish evaluation tooling and verify the committed baseline

**T01 — Formal DNS-tunnelling scorer. P0; TOOLING COMPLETE (15 October 2026).**

Outcome: [scorer freeze](DNS_TUNNELLING_SCORER.md), 61 new cases and 131 targeted
tests passed. Existing runtime/gates unchanged; reserved CLI refuses before data
access/receipt creation. Final data qualification/scoring still depends on T30.

- Problem: the development evaluator counts any alert and is not sufficient for
  final-query-only FN and joint timing gates. Runtime configuration is now frozen.
- Affected: `datasets/evaluate_dns_tunnel_candidate.py` (retain as development),
  `data/dns_tunnel_evaluation_contract.json`, new minimal offline formal scorer and
  its tests. Reuse existing runtime/parser; do not create another detector.
- Required: session-level TP/TN/FP/FN, precision/recall/F1/FPR; first-alert query
  and capture delay; final-query-only FN; query<=10 AND delay<=10s for >=90% of TPs;
  undefined denominators; every TP before completion. Validate source/config and
  manifest integrity, coverage/disjointness and single-pass controls before scoring.
  Test calculations with existing fixtures; never consume reserve to debug a scorer.
- Dependencies: frozen current DNS contract (done); new final data NOT needed for
  implementation. Actual final scoring stays blocked on T30.
- Tests: no-alert, early alert, final-only alert, benign alert, repeated alerts,
  timing boundary/either-condition failure, empty denominators, changed hash,
  missing control/labels, duplicate session/fragment, refused repeated final run.
- DoD: deterministic tested scorer, pinned source and invocation contract, no
  reserved reads and no runtime/threshold change. Record its evidence separately.

**T02 — Clean checkout of the committed snapshot. P1; COMPLETE (15 October 2026).**

Outcome: [current reproduction](CLEAN_CHECKOUT_20261015.md), corrected local commit
`a12eb48`, 443 backend tests passed/two optional PyArrow skips, typecheck/build,
incremental production demo and unchanged restart history. Declared TypeScript
range now matches the lockfile; regression reproduces the old failure. Remaining
dependency advisories and unpublished remote state are disclosed. Freeze this
verification; the final release still requires its separate post-integration run.

- Problem: older clean-checkout evidence predates the current committed additions.
- Affected: README, lockfiles/packaging, `.gitattributes`, setup scripts and tests.
- Required: new directory and isolated Python/npm installations using README only;
  verify hashes, startup, full tests, typecheck/build, default replay and persisted
  alerts. Bundled demo must work without research raw datasets or developer caches.
- Dependencies: current commit; repeat final check after all accepted runtime work.
- Tests: fresh-environment demo and documented commands, Windows checkout bytes;
  record platform limits rather than claiming untested Linux support.
- DoD: reproducible logged installation/demo with no undocumented fixes. Fix setup
  defects only; do not retrain models as a setup step.

## Phase 2 — close active-baseline quality blockers, one subtype at a time

**T20 — Observability and next-experiment decision. P0; COMPLETE FOR UDP, C2 AND SUSPECTED-SPOOF DIAGNOSIS (17 October 2026).**

T22 outcome: [suspected-spoof decision](SPOOF_OBSERVABILITY_DECISION.md), four
exact first-FP HYBRID reproductions, three full opposite-label metadata/runtime
collisions and an additional telemetry collision in the disabled diagnostic
feature sequence. Nineteen new cases; 66 targeted spoof/baseline/UDP/C2 checks
pass. Original TP4/TN2/FP4/FN0 and failed gates remain; subtype stays disabled.
No runtime/model/threshold change or reserve. T22 is blocked on independently
labelled lab provenance plus genuinely separating passive evidence, not tuning.

C2 outcome: [diagnostic decision](C2_OBSERVABILITY_DECISION.md), two exact first-FP
reproductions (one HYBRID, one ML), full health-check/beacon metadata collision,
and three slow/rotating misses explained by the unchanged causal horizon/count
guard. Thirteen new cases; 41 targeted C2/baseline/UDP checks pass. Historical C2
quality remains TP3/TN6/FP2/FN3; no runtime/training/gate change or reserved access.
T23 remains blocked on independently labelled matched-periodicity development
evidence and contact-versus-packet visibility, not on another threshold trial.

Outcome: [UDP decision](UDP_OBSERVABILITY_DECISION.md), four first-FP HYBRID
reproductions and exact full-runtime feature collision for flood/video metadata
that differs only by destination port. Seven new tests; 23 targeted checks pass.
No runtime/model/threshold change. One same-service matched-load development-pair
qualification is recommended, not implemented. T21 remains data/visibility blocked;
no threshold or training experiment is currently justified. This does not complete
the observability work for remaining subtypes or accept the UDP detector.

- Problem: baseline failure analysis found exact opposite-label metadata pairs and
  feature-only collisions. Repeated threshold/model trials cannot resolve all of
  them. The fingerprint ablation was already completed and rejected; do not rerun it.
- Affected: `BASELINE_FAILURE_ANALYSIS.md`, current per-threat validation protocols,
  `detection/pipeline.py`, `features/extractor.py`, existing development generators.
- Required: for ONE chosen subtype distinguish observable behavior from hidden
  intent; retain every hard negative. Identify whether genuinely observed causal
  metadata can address a measured representation defect. Define ONE smallest
  development experiment and its non-regression criteria before implementing it.
- Dependencies: existing diagnosis; no new reserved observations.
- Tests: exact metadata/feature-pair comparison and rule-versus-model attribution.
- DoD: one evidence-based experiment ready for an explicitly scoped implementation
  task, or an explicit visibility/data blocker. No runtime change in this package.

**T21–T26 — Per-detector quality closure. P0; DEPENDS ON T20.**

T25 diagnosis update, 18 October 2026 IST: [exfil decision](EXFIL_OBSERVABILITY_DECISION.md)
reproduces 3 RULE/1 ML first FPs with exact wording, verifies four complete
opposite-purpose collisions and causal byte/ratio semantics. Twenty-four new
cases; 121 targeted regressions pass. No runtime/model/gate change or new quality
evaluation. T25 remains unresolved; next current-baseline full tests/build only.

T24 diagnosis update, 18 October 2026 IST: [recon decision](RECON_OBSERVABILITY_DECISION.md)
reproduces three ML-only FPs, two complete opposite-authorization metadata/runtime
collisions and a distinct service-discovery prefix overlap. Six-host slow-window
limit verified without prediction. Twenty-two new cases; 86 targeted tests pass.
No runtime/model/gate change, new quality matrix or reserve. T24 quality remains
unresolved; next independent eligible package under continuous authorization is T25.

T22 qualification update, 17 October 2026: [source screen](SPOOF_PAIR_QUALIFICATION.md)
and `data/spoof_pair_qualification.json` record BLOCKED_NOT_QUALIFIED after five
bounded metadata-only leads. No independently labelled forged/genuine original
capture pair on the same UDP application/port is established; load overlap is
unmeasured. Obtain the BOUN producer provenance/run bundle before packet values.
No detector experiment, training, reserved scoring or new message; failed subtype
remains disabled, all gates unchanged. Qualification DoD has not passed.

T23 contact update, 17 October 2026: the exact TQH clarification was explicitly
approved and sent once. [Sent status](C2_TQH_CONTACT_STATUS.md) pins recipient,
approved text and Gmail evidence. Delivery/reply remain unknown; qualify producer
contact/application records before packet values. No runtime/model/gate change.
The earlier pending-approval status below is historical and superseded.

T23 qualification update, 17 October 2026: [C2 source screen](C2_PAIR_QUALIFICATION.md)
and `data/c2_pair_qualification.json` record NO QUALIFIED PAIR after four bounded
publisher leads. The pre-value protocol is frozen; executed-contact joins and a
named matched periodic benign application remain missing. Prepared TQH producer
clarification is not sent; new-recipient approval is required. No detector/model
change, new packet/annotation value inspection, training or reserved scoring.

T21 qualification update, 16 October 2026: [source screen](UDP_PAIR_QUALIFICATION.md)
and `data/udp_pair_qualification.json` record NO QUALIFIED PAIR. Same-service benign
run provenance is absent; load overlap is unmeasured. The pre-value qualification
protocol is frozen. No detector experiment, training or reserved scoring. Obtain
the producer runbook before capture inspection; stop while that blocker remains.

Order: UDP flood (T21), suspected spoofed-source indicators (T22), C2 (T23), recon/
port scans (T24), possible exfiltration (T25), then SYN non-regression (T26).
Skip ahead only to independent eligible work when the current package is blocked.

- Affected: `datasets/validate_udp_flood.py`, `validate_spoofed_source.py`,
  `validate_c2_beacon.py`, `validate_recon.py`, `validate_exfil.py`,
  `validate_syn_flood.py`; corresponding protocol/report and narrow runtime paths.
- Required: preserve each existing gate, introduce only the agreed causal feature/
  rule correction, compare on development, freeze choices, then assess a genuinely
  independent qualified set. Do not recycle consumed evaluation sets as reserve.
- Controls: legitimate bulk UDP/QUIC/DNS and distributed clients; periodic health/
  update/telemetry/polling; authorized scans/discovery/inventory/monitoring; cloud
  backup/upload/sync/replication. Preserve reverse-unavailable versus observed-zero.
- Tests: per-subtype causal accounting, evidence, early alerts, hard negatives;
  full backend/build after shared changes. Passing SYN behavior is not a redesign
  target; rerun it only when integration changes justify it.
- DoD per subtype: frozen gate passes within documented scope, or unresolved
  decision with failed candidates disabled. Do not claim forged addresses,
  reflection, malicious authorization or stolen content is passively proven.
- Release DoD: unresolved required-quality BLOCKERs cannot be marked complete by
  merely relabelling them experimental. Escalate irreducible visibility limits.

## Phase 3 — resolve the three data-dependent detector tracks

T30 public-provenance follow-up, 17 October UTC / 18 October IST:
[UMA decision](DNS_UMA_PROVENANCE_DECISION.md) finds only public template manifests
and descriptive window-comparison instructions, not executed DNS session labels.
Five pinned text documents verified; no new data rows/headers or source roles.
Keep T30 blocked; continuous-work authorization permits independent T24 diagnosis.

T30 downloaded-source qualification, 17 October 2026: [decision](DNS_PUBLIC_DATA_QUALIFICATION.md)
records no eligible final set. DNSTunnel2026's actual catalogue is nested
train/test CSVs plus model/README; original query/run truth is not established.
UMA has 45 nominal PCAPNGs, no bundled session sidecars; ZIP method 9 is unsupported
by Python and native tar returned no header bytes. Actual format/visibility remain
unverified. No installation/conversion, rows, training, role assignment or scoring.
Next review public executed-run/client-log provenance; T30 remains source-blocked.

T30 acquisition update, 17 October 2026: the two user-approved Zenodo ZIPs are
downloaded and size/publisher-MD5 verified (7,351,027,624 original bytes total).
See [acquisition report](DNS_PUBLIC_DATA_ACQUISITION.md) and
`data/dns_public_acquisition.json` for local paths, SHA256 and reproduction.
Acquisition DoD passes; no extraction/data rows, runtime integration, training,
reserved assignment/scoring or candidate activation. Source/label/format/coverage
qualification remains required before use; the T30 final quality blocker remains.

T30 alternative-source update, 17 October 2026: user chose publicly licensed data.
[Five-source DNS screen](DNS_OPEN_SOURCE_ALTERNATIVES.md) verifies two open CC BY
4.0 releases without needing a reply for their declared rights. Neither they nor
the other three leads establish the entire frozen original-question/session/tool/
benign-control contract. No traffic values, archive download, training, runtime
change or reserve assignment/scoring. T30 remains blocked on qualified evidence;
the next prerequisite is an original dnscat2/iodine release with executed-session
annotations plus documented benign categories. Existing requests are not resent.

These can progress as independent research tracks, but each actual implementation
and reserved evaluation is a separate scoped task. Do not mix/tune their data.

**T30 — DNS-tunnelling qualification, evaluation and conditional promotion. P0;
SOURCE BLOCKED.**

- Affected: DNS gap/contract/source-review docs, capture manifests, T01 scorer,
  existing candidate and parser. Maintainer clarification is already posted as
  https://github.com/Korving-F/dns-tunnel-dataset/issues/3; do not duplicate it.
- Required: establish capture rights, compatible original format, complete DNS,
  independent session truth/time joins and benign strata. Resolve `-i any` risk
  from actual permitted artifact headers, not file extension. Freeze bounded
  acquisition/roles before raw values; verify hashes, joins and disjointness.
- Gates: >=20 positive/50 benign independent sessions; five benign categories;
  recall>=80%, precision>=95%, benign-session FPR<=2%; original timing conditions.
  Report true tool/type/rate coverage and unsupported observations without invention.
- Dependencies: qualified source bundle, T01, frozen session manifest/scorer.
- Tests: integrity, parser visibility, manifest/scorer cases; one reserved pass only.
- DoD: recorded decision. If passed, separate minimal runtime-promotion task with
  full regressions/build/replay. If failed/unassessed, no promotion or gate reduction.

**T31 — DGA final data and evaluation. P0; SOURCE BLOCKED.**

- Affected: frozen DGA protocol/design, acquisition/exclusion manifests, candidate
  reports and `ml/dga_oof_candidate.json`. Existing clarification sent to Marques.
- Required: finish known alias/exposure exclusions; obtain five legitimate strata
  with 600 eligible labels each and independent benign DNS >=2,500 eligible unique
  first labels. Finish cross-role overlap and provenance checks before final
  materialization. Positive counts remain provisional until all exclusions pass.
- Gates: recall>=80%, precision>=95%, domain FPR<=2%, separate benign-DNS FPR<=2%.
- Dependencies: qualified original names/service context and frozen final manifest.
- Tests: source/alias/disjointness/hash/canonicalization and runtime feature parity.
- DoD: single reserved evaluation of already-frozen choices; no automatic retraining.
  Passing artifact/hash/report precedes a separate explicit runtime-promotion task.
  Failing candidate stays disabled with family/FP/FN analysis.

**T32 — Encrypted-session coverage and validation. P0; SOURCE BLOCKED.**

- Affected: frozen encrypted coverage plan and qualification scripts, causal TLS
  feature contract, current experimental artifact and validation docs. ARES author
  clarification already sent; delivery/answers must be established, not assumed.
- Required: satisfy the frozen independent framework/source/environment/run roles,
  verified session intent, complete ClientHello timing and browser/updater/API/
  ordinary-app controls. Three TLS-capable framework and source groups across
  roles, two runs per role and development JA3 counterexamples remain prerequisites.
- Dependencies: source qualification and role assignment before raw-value access;
  no training until all coverage requirements pass.
- Tests: label/time joins, capture visibility, family/group isolation, causal
  training/runtime parity and shortcut controls; no decryption or invented QUIC
  fingerprint extraction.
- DoD: freeze a lightweight candidate only after readiness; train/tune on permitted
  development roles; one reserved pass against the existing encrypted gates. A
  passing decision still needs separate runtime integration/regressions. Failed
  candidates stay disabled; raw QUIC capability is not silently claimed.

## Phase 4 — safely integrate only accepted changes

**T40 — Promotion and application non-regression. P1; CONDITIONAL ON PASS.**

- Affected: only approved artifact/config/loading and affected detector; existing
  alert API/schema, SQLite, SSE, replay, upload and Monitor consumers.
- Required: reference previous artifact, verify approved SHA before activation,
  preserve evidence/score-vs-severity semantics and incremental output; no unrelated
  feature/model changes. Keep analyst history and source datasets intact.
- Tests: affected detector plus full backend, typecheck/build, public replay where
  eligible, persistence/restart, SSE resume, replay failures, uploads, desktop/
  tablet/mobile smoke. Use disposable databases and qualified control inputs.
- DoD: accepted candidate safely integrated with unchanged contracts; no lost or
  duplicated analyst records. If integration reveals a real defect, fix/test that
  defect before proceeding. Do not reopen passed UI work for cosmetic changes.

## Phase 5 — final reliability, security and performance evidence

**T50 — Scoped hardening and failure recovery. P1; AFTER FINAL INTEGRATIONS.**

Dependency-only precursor completed 16 October 2026: [triage/fix](DEPENDENCY_SECURITY_TRIAGE_20261016.md)
resolves the two recorded npm package findings with patch updates, zero current
npm advisories, 455 backend passes and production proxy/SSE smoke. Freeze that
scoped result; this does not complete final T50 or clear detector/data blockers.

- Affected: current API/config/upload/error/logging/persistence paths only.
- Required: confirm loopback binding, upload bounds/temp cleanup, safe path handling,
  input validation, non-leaking errors, model integrity and DB/SSE failure recovery.
  Keep final data permissions/private material out of public publication.
- Tests: reuse existing negative/regression tests; add one for each new defect.
- DoD: no unresolved demo-critical failure/security gap; clearly document local-only
  scope. Public deployment or multi-user auth is a separately approved scope.

**T51 — Rerun declared benchmarks. P1; AFTER FINAL RUNTIME CHANGES.**

- Affected: existing `benchmarks.run`, `benchmarks.delivery`, separate dated reports.
- Required: core>=2,000 metadata events/s, processing+SQLite p95<50ms; >=100
  deterministic API/persistence/SSE alerts, none lost, loopback p95<1,000ms.
  Record machine/Python/source hashes, workload, elapsed time, alert counts and
  available percentiles. New output paths; preserve old reports.
- Tests: reproducible runners and exact alert identity matching. If a regression
  appears, identify its stage before minimal optimization.
- DoD: both scoped gates pass on final source. Do not claim capture-to-browser or
  physical deployment throughput; no new cache/broker/distributed infrastructure.

## Phase 6 — final reproducibility and judge demonstration

**T60 — Final clean-checkout and demo rehearsal. P1; AFTER T40/T50/T51.**

- Affected: README/setup, bundled artifacts, demo manifest/CLI and Monitor.
- Required: repeat T02 on final revision; verify one benign plus all seven threat
  labels with deterministic replay fallbacks, hashes, expected evidence/timing and
  limitations. Rehearse startup → replay → live evidence → failure recovery.
- Tests: clean install, complete suite, typecheck/build, UI smoke and demo preflight;
  manual rehearsal without relying on pending downloads, publisher availability or
  developer environments. Never call synthetic success real-data accuracy.
- DoD: another team member can reproduce the demonstrated local application using
  only the documented instructions, with no unrecorded fixes.

## Phase 7 — documentation, release audit and publication

**T70 — Reconcile final docs. P1; AFTER MEASUREMENTS.**

- Affected: README, EXPECTED_SOLUTION, MODEL_AND_VALIDATION, DATASETS,
  STREAMING_VALIDATION, STREAM_RELIABILITY, performance/demo docs and completion plan.
- Required: exact per-threat data/features/rule/model, deployed-vs-disabled state,
  evaluation scope/counts/FPs/limitations, hash/provenance and throughput scope.
  Add dated supplements; do not mutate frozen historical reports to imply reruns.
- Tests: reference/command/hash review and agreement with actual runtime flags.
- DoD: no stale result presented as current, no unmeasured accuracy/completion claim.

**T71 — Final requirement audit and publish. P0 RELEASE GATE; LAST.**

- Required: requirement/status/evidence/limitation matrix covering passive design,
  all threats, quality gates, causal/bounded streaming, application, performance,
  reproducibility and dataset/model rights. Classify BLOCKER/HIGH/MEDIUM/LOW.
- Dependencies: all required packages above have accepted, source-matching evidence.
- Tests: verify final source/artifact/report identities and clean Git state.
- DoD: no BLOCKER remains before `FINAL SIH RELEASE STATUS: READY`. Commit final
  source/docs/reports; push only with user authorization. Existing local commit is
  not evidence that the remote already contains it.

## P2/P3 work — explicitly deferred

Broader performance characterization, physical-device accessibility/motion checks
and dependency deprecation cleanup can follow demonstrated needs. Cosmetic
animation additions are optional. Native flow-export collectors, PCAPNG/cooked
formats, raw QUIC fingerprints, enterprise auth, cloud hosting and infrastructure
expansion are future scope; none substitutes for unresolved mandatory quality.

## Start here

**Next incomplete package: T21, qualified same-service UDP development evidence.**
T01/T02 and the UDP T20 decision are complete/frozen. T21 is data/visibility blocked;
the proposed qualification experiment has not been implemented. Independent work
requires its own explicit scope. Do not automatically train candidates or
manufacture a completion deadline while external data qualification is unresolved.

**UMA signature supplement, 18 October 2026 IST:**
[Bounded header decision](UMA_HEADER_TRANSPORT_DECISION.md) confirms all 45 members
have the PCAPNG signature using an already installed decoder: only four bytes per
member, no packet parsing/conversion or dependency change. Eight transport tests
pass. Runtime format support and independently labelled DNS-control coverage remain
missing; roles/gates/candidate state unchanged. This supplements the earlier
header-unverified record without rewriting its frozen historical evidence.

**Clean-checkout checkpoint, 18 October 2026 IST:**
[Current report](CLEAN_CHECKOUT_20261018.md) verifies local `4e92b3b`: fresh install,
531 backend tests/three optional research skips, typecheck/build, nine-fixture
preflight and controlled incremental 256-event/15-alert/seven-class browser replay
pass. Core 3,473.57 metadata events/sec/p95 0.9922 ms; 100/100 loopback deliveries,
p95 245.8072 ms. Original history/artifacts untouched. Full rehearsal remains
PARTIAL because restart was not repeated before the unattended window elapsed.
Next: isolated restart check using saved actual 30-record history; all detector
quality gates and release blockers remain unchanged.

**Restart completion, 18 October 2026 IST:**
[Verification](RESTART_COMPLETION_20261018.md) closes the interrupted current
clean-checkout restart task: two production lifetimes preserve all 30 records,
15-record SSE catch-up has zero duplicates, Monitor reconnects and five existing
regressions pass. No runtime/model change; 130 protected originals unchanged.
[Execution sequence](COMPLETION_EXECUTION_20261018.md) records remaining priorities,
dependencies and acceptance. Next is T21 source qualification, still provenance/
visibility blocked. Final detector quality, final T60 and release remain unresolved.

**API cursor validation, 19 October 2026 IST:**
[Correction](API_CURSOR_VALIDATION_20261019.md) prevents oversized query/header
cursors reaching SQLite or starting a broken SSE response. Eight new regression
cases; 549 backend tests, typecheck/build/demo pass. All nine expected demo traces
unchanged; only API source provenance/checksum refreshed. Fresh direct loopback
delivery 100/100, p95 246.01 ms. Models/research gates/history unchanged. This is a
T50 precursor, not final release closure. Next: bounded upload-storage failure check.

**Upload storage recovery, 19 October 2026 IST:**
[Fix](UPLOAD_STORAGE_RECOVERY_20261019.md) covers staging allocation/write/close
failures with cleanup and generic HTTP 503; interrupted uploads and existing
history remain intact. Eight new cases; 41 targeted/557 full backend tests,
TypeScript/build/demo pass. Frozen nine expected traces unchanged, only API demo
source provenance refreshed. Direct delivery 100/100, p95 244.69 ms. Independent
T50 precursor only; model/data gates unchanged. Next: bounded outstanding-source
clarification review; no outgoing message or automatic training/promotion.

**Outstanding-source review, 19 October 2026 IST:**
[Bounded review](SOURCE_PREREQUISITES_20261019.md) finds no incoming match for the
existing DGA/C2/TLS request query; DNS Issue #3 is open with zero comments. No new
qualified provenance bundle, data, scoring, model change or outgoing message.
Source-dependent tasks remain BLOCKED. Next independent task: Monitor verification
of the newly fixed upload-storage feedback/recovery with isolated test injection.

**Monitor upload integration, 19 October 2026 IST:**
[Scoped verification](MONITOR_UPLOAD_FEEDBACK_20261019.md) confirms real storage
503/error feedback, same-file retry, malformed 422 and subsequent recovery at
desktop/tablet/mobile sizes. Zero console errors/page overflow; all 130 protected
originals unchanged. No frontend or detector change; normal production proxy build
restored after isolated testing. Next independent package: SQLite read-error API
response verification. Data-dependent quality and release gates remain blocked.

**Next hardening checkpoint, 19 October 2026 IST:**
[Read-error diagnosis](SQLITE_READ_DIAGNOSIS_20261019.md) reproduces controlled
SQLite read failures: alerts/telemetry 500 and initial SSE 200 then failure.
Original fixture records recover unchanged; all 130 protected originals preserved.
No production repair started near the session cap. Exact next task is narrow
503/read-boundary and deterministic SSE recovery with regressions. Latest completed
source remains 557 passing tests, TS/build/demo and delivery checks. All required
data/intent-quality blockers remain; no promotion or release declaration.

**SQLite read recovery, 19 October 2026 IST:**
[Verified repair](SQLITE_READ_RECOVERY_20261019.md) returns safe alert/telemetry/
initial-SSE 503 for SQLite read failures; late stream faults close cleanly for
sequence resume. Seventeen new regressions, 46 targeted and 574 canonical backend
passes (one existing warning), TypeScript/build/nine demo scenarios pass. Real
loopback fault/resume preserves three records, two caught up with no duplicate;
fresh 100-alert delivery p95 252.68 ms. Only API demo source pin/checksum refreshed
after unchanged traces; 128 other protected originals unchanged. Supplementary
global-Python 566-pass/one-module-skip run is retained; the .venv rerun has no skips.
DoD PASS; behavior/tests/metrics/limitations frozen. Next: isolated Monitor storage-
read error/reconnect integration, preserving its existing design. No training,
reserved scoring, model promotion, new external request or release READY.

**Monitor history-read recovery, 19 October 2026 IST:**
[Production-proxy verification](MONITOR_READ_RECOVERY_20261019.md) passes desktop,
tablet and mobile outages: retained queues 2/4/6, recovered queues 4/6/8, SSE
catch-up sequences 3..8 exactly once. Fresh-load recovery and recovered alert ID/
flow/evidence match pass. Thirty existing regressions, typecheck and configured/
restored-default builds pass; 130 protected originals unchanged. No product/test
suite/model/gate/provenance change. Optional clipboard contents remain unverified
because the browser capability returned empty despite UI feedback. Freeze scoped
DoD PASS. Next incomplete T21 qualification remains blocked on a verified producer
runbook; no new message/mail check, packet values, scoring, promotion or READY.

## T21 qualification follow-up — 19 October 2026 IST, 11:46

[Scoped recheck](UDP_PAIR_RECHECK_20261019.md) against `b02a8de` verified the exact
incoming ORION query/account and a settled "No messages matched your search"
result. This is a point-in-time search, not proof of delivery or exhaustive absence.
The producer runbook, matching benign application/service, independent paired-run
labels and original-time provenance remain unverified. T21 qualification DoD is
NOT MET / BLOCKED, with no selected pair, packet inspection or detector experiment.
The frozen protocol/manifest and 130 protected original files are unchanged;
12 existing UDP regressions pass. No message/resend/monitoring, download, reserved
scoring, training or promotion. Next T21 action: verify actual producer evidence
before the already frozen packet-format/load-overlap qualification can start.

## T21 alternative-source acquisition — 19 October 2026 IST

[Bounded screening](UDP_ALTERNATIVE_SOURCES_20261019.md) identified NetsLab iPerf
benign/two UDP-flood capture names under a producer CC BY 4.0 deposit. Two bounded
metadata passes agree on names/directory hashes; no traffic members decompressed.
Service/run/timing evidence and full capture integrity remain unverified, so the
pair remains NOT QUALIFIED. Missing HTTP identity headers are explicitly recorded,
not imposed as a new T21 gate; stricter draft failures are retained. Ten new tool
cases plus 12 UDP regressions pass, all 130 protected originals unchanged. A precise
NetsLab clarification draft is prepared NOT SENT; new-recipient approval or an
explicit isolated-lab collection scope is needed next. No runtime/model/gate/data
change, packet values, training, scoring, new external message or promotion.

## T21 NetsLab dispatch and public-only route — 20 October 2026 IST

The user approved the exact prepared request to the NetsLab corresponding author
and selected **public datasets only**. [Dispatch verified](UDP_NETSLAB_RUNBOOK_STATUS.md):
one Send click, Gmail Message sent and opened Sent envelope/body match; no CC/BCC
or attachments. The historical prepared file is preserved unchanged. This
supersedes the pending-send/lab-option next action in the dated 19 October entry.
Delivery/reply and pair qualification remain unverified. T21 stays BLOCKED / NOT
QUALIFIED; no packet values, detector experiment or gate change. Next: verify
original producer service/run/label/timestamp and format/integrity evidence before
packet inspection and the frozen original-time overlap screen. If no public
source meets the prerequisites, record the blocker without substituting lab data.

## Public-only acquisition route — 20 October 2026 IST

The user instructs skipping email-gated sources and supplemental annotations.
[New route and source screen](PUBLIC_DATA_ROUTE_20261020.md) preserves all prior
public inputs/roles; no further mail, institutional details or lab collection.
Four additional public leads were metadata-screened; zero qualify as missing
C2/DNS/DGA evaluation replacements. No raw data rows, scoring, training, runtime
change or relaxed gate. Earlier pending-response next actions are superseded;
source qualification must be established from published records. Existing quality
blockers remain unresolved; no release READY. See data/public_source_route.json.

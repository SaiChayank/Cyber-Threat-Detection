# Remaining implementation sequence

**Execution checkpoint, 19 October:** cursor validation, PCAP staging-storage and
[SQLite read recovery](SQLITE_READ_RECOVERY_20261019.md) are fixed and verified.
Latest source: 574 backend tests, TypeScript/build/nine-scenario demo pass; direct
delivery 100/100, p95 252.68 ms. [Monitor database-read recovery](MONITOR_READ_RECOVERY_20261019.md)
now passes three viewports through the production proxy: retained rows, six exact
catch-up deliveries, initial-load recovery; no product change. Thirty targeted
regressions/typecheck/build pass, all 130 original hashes unchanged. Next incomplete
task: T21 producer-runbook/pair qualification. A [focused response recheck](UDP_PAIR_RECHECK_20261019.md)
still found no incoming ORION match; qualification remains blocked without verified
source evidence. [Alternative acquisition](UDP_ALTERNATIVE_SOURCES_20261019.md)
identified public NetsLab iPerf/UDP-flood capture members and verified their ZIP
directory metadata, but matching service/run/timing evidence is still missing.
A precise clarification was prepared on 19 October. On 20 October the user approved
and Gmail verified the [NetsLab request dispatch](UDP_NETSLAB_RUNBOOK_STATUS.md).
The user selected public datasets only; isolated-lab collection is not the route.
T21 remains unqualified pending producer evidence. No packet values or experiment.
This supplements the sequence below; detector/research gates unchanged.

18 October 2026 IST. Baseline `49855bc`; execution supplement to
`REMAINING_WORK_PLAN.md` and the frozen per-detector protocols. The approximate
7/10 rating is an engineering judgement, not a measured completion percentage.
Retain the current local architecture and all passed components. No new framework,
database, authentication system, capture format or infrastructure is required by
this plan. No deadline or model result is promised while data/visibility blockers
remain unresolved. Commit each completed, verified work package; no push here.

## 1. Close the current reproducibility checkpoint — P1, COMPLETE

Outcome: [restart completion](RESTART_COMPLETION_20261018.md), exact 30-record
continuity across two new production lifetimes, 15-record SSE catch-up without
duplicates, connected Monitor reload and five targeted regressions passing.
No runtime/model change. The remaining phases below retain their dependencies.

- Problem: the latest clean installation/build/demo/performance checks pass, but
  its restart step was interrupted. The isolated clone now has 30 real persisted
  records: the controlled 15 plus a later independently triggered replay.
- Modules: existing launcher, `persistence/store.py`, API alerts/telemetry/SSE,
  Monitor; dated verification scripts/reports only unless a real defect appears.
- Implementation: reuse the isolated checkout and its saved actual history;
  compare all IDs/order/evidence before/after production lifetimes. Verify idle
  runtime reset, pagination/filtering and sequence-based SSE catch-up. Keep every
  record, original analyst database and historical evidence intact.
- Dependencies: existing checkout, saved 30-record snapshot, unused local ports.
- Tests: existing SQLite restart and SSE resume tests; actual production proxy
  comparison and browser reload. No replay/new alert is needed for this check.
- DoD: 30 unchanged records across restart, no gap/duplicate in resumed delivery,
  fresh idle telemetry and Monitor recovery; original protected files unchanged.
  This closes the current rehearsal only, not final T60 or detector quality.

## 2. Qualify missing independent data — P0, BLOCKED BY PROVENANCE/COVERAGE

Work on one source track at a time, metadata/provenance before packet values.
Existing requests must not be duplicated; this plan does not authorize messages.

- UDP T21: producer-labelled flood/benign runs on the same UDP application/port,
  original timing and overlapping load. Modules: UDP qualification manifest,
  runbook protocol and `datasets/validate_udp_flood.py` development evidence.
- Suspected spoof T22: independently verified forged/genuine lab runs, same UDP
  service/load and separating passive evidence. Address diversity alone cannot
  prove source forgery. Modules: spoof qualification/diagnosis and validator.
- C2 T23: executed beacon-contact timestamps joined to sessions plus a matched
  periodic benign application. Modules: C2 qualification/diagnosis and validator.
- DGA T31: resolve family aliases/exposure exclusions, five legitimate strata
  with 600 eligible labels each, independent benign DNS with >=2,500 eligible
  unique first labels, and frozen source/family-separated roles.
- DNS tunnel T30: compatible original observations, executed session/time truth,
  >=20 independent positive and >=50 benign sessions, required tool coverage and
  five benign categories. UMA magic is PCAPNG; its 45 filenames are not session
  truth and the downloaded ZIP does not justify extending runtime support.
- Encrypted T32: independent TLS-capable framework/source/environment/run roles,
  verified session intent and ClientHello timing, plus browser/updater/API/normal
  application controls. Training remains blocked by the frozen coverage plan.
- Tests/DoD per track: permissions, byte hashes, source/label/time joins, original
  chronology, counts, duplicates, role disjointness and documented visibility all
  pass before any new evaluation values or training. Otherwise record BLOCKED.

## 3. Resolve observable-behaviour limits — P0, CONDITIONAL

- Problem: recon and exfil development pairs have identical visible metadata
  with opposite hidden authorization/purpose; C2/flood pairs also collide. More
  model complexity or threshold tuning cannot separate identical observations.
- Modules: `RECON_OBSERVABILITY_DECISION.md`, `EXFIL_OBSERVABILITY_DECISION.md`,
  corresponding C2/UDP/spoof decisions, frozen validators and narrow detector paths.
- Required: establish genuinely available passive distinguishing context from
  independently labelled runs. If unavailable, obtain an explicit project-scope
  decision; do not silently change labels, official coverage or acceptance gates.
- Tests: exact collision/control regressions and causal feature parity; every
  prior hard negative retained. SYN stays frozen unless integration exposes a bug.
- DoD: one justified, preregistered development experiment per detector, or an
  explicit unresolved visibility blocker. No claimed proof of forgery/reflection,
  malicious intent or confidential content theft from metadata alone.

## 4. Run eligible experiments and freeze evaluation — P0, AFTER 2/3

- Modules: existing feature extractors, rules, lightweight model code, validation
  scripts, frozen manifests and reports. Modify only the active detector.
- Required: smallest evidence-supported change using causal runtime-compatible
  features; train only where authorized and on approved training data; tune only
  on validation. Compare deployed baseline/rule/candidate and per-family/scenario
  errors. Freeze choices before the single reserved pass.
- DGA gates remain recall >=80%, precision >=95%, domain FPR <=2% and independent
  benign-DNS FPR <=2%. DNS gates additionally retain all frozen session/timing
  requirements. Other detector gates remain exactly as their protocols declare.
- Tests: exact features, parser visibility, causal windows, missing values,
  training/serving parity, hard negatives and runtime cost.
- DoD: gate-backed decision and artifact/report/hash if applicable. Failure means
  disabled plus FP/FN analysis and ONE recommended experiment, not automatic retry.

## 5. Integrate accepted changes — P1, CONDITIONAL ON PASS + PROMOTION TASK

- Modules: only approved artifact/configuration and affected detector; existing
  alert schema, SQLite, API/SSE, replay, upload and Monitor consumers.
- Required: verify approved SHA before activation, reference old artifact, preserve
  incremental alerts, evidence and score-versus-severity meaning. No data loss.
- Tests: affected regressions, full backend suite, TypeScript/build, qualified
  replay, persistence/restart/resume and desktop/tablet/mobile functional smoke.
- DoD: accepted detector safely integrated with unchanged consumer contracts.
  A passing offline result is not permission to activate an unrelated candidate.

## 6. Final reliability, security and performance — P1, AFTER INTEGRATIONS

- Modules: existing API/upload/errors/SQLite/model integrity/dependencies; existing
  benchmark runners. No enterprise infrastructure or unrelated refactoring.
- Required: negative/failure recovery checks, loopback scope, safe uploads/temp
  cleanup, non-leaking errors, dependency triage and frozen artifact integrity.
- Tests: regressions for each discovered defect; >=20,000 metadata-event core run
  and >=100 deterministic API/persistence/SSE alerts on final source.
- DoD: no demo-critical application defect; core >=2,000 events/sec and processing
  + SQLite p95 <50 ms; loopback API-to-SSE p95 <1,000 ms with all IDs matching.
  Preserve benchmark scope; no raw-capture-to-browser throughput claim.

## 7. Final demo, documentation and release audit — P1/P0, LAST

- Modules: README, demo pack, model/data/streaming/reliability docs, completion plan
  and final requirement matrix. Preserve dated reports and provenance hashes.
- Required: final clean checkout following README, all demo fallbacks/evidence,
  one benign plus required threat coverage, failure recovery, current measured
  reports and accurate deployed-versus-disabled disclosures.
- Tests: full backend, TypeScript/build, responsive Monitor, model/demo hashes,
  restart/SSE and final scoped benchmarks; dataset rights/provenance review.
- DoD: every official requirement has accepted evidence and no BLOCKER remains
  before READY. Publish only with authorization; local commits are not remote proof.

## Deferred P2/P3

Cosmetic animations, broader physical-device/accessibility review, additional
performance characterization and dependency deprecation cleanup follow concrete
needs. PCAPNG/cooked formats, raw QUIC fingerprints, multi-user auth and hosting
remain separate future scope. They must not replace the required quality work.

## Working foundations to retain

Next.js/React Monitor, FastAPI, SQLite alert history, incremental rule/GNB pipeline,
causal feature extraction, SSE resume, replay/upload controls, exact model hashes,
deterministic bundled demo and scoped benchmark tools. Current installation/tests/
build/performance successes do not establish production or public-data accuracy.

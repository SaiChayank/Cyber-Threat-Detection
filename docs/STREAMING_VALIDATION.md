# Validation evidence and report currency

Audited **2 October 2026**. This index distinguishes deployed behavior, synthetic
regressions, public-data experiments and disabled candidates. No captures were
replayed, models trained, reserved data inspected or measurements rerun for this
documentation task. Original JSON measurements and their source hashes are retained.

**Subsequent release audit:** [Final release audit](FINAL_RELEASE_AUDIT.md) records
fresh controlled reruns, 225 clean-checkout tests, production UI/build checks and
new scoped benchmark runs. The historical table below classifies the original
saved reports; it is not a claim that the later audit did not occur. The new
controlled counts remain unchanged and detector-quality blockers remain unresolved.
Three inactive public-model artifacts fail byte integrity in Windows checkout.

## Which evidence is current

“Source-matching” means the report's recorded runtime/benchmark hash set matches
the audited files. It does not extend a report beyond its recorded workload or
establish production accuracy. A report without a full runtime hash set cannot be
called a final-runtime evaluation merely because its model artifact still exists.

| Saved evidence | Scope and measured result | Currency / interpretation |
| --- | --- | --- |
| `benchmarks/latest.json`, 1 Oct 12:10:58 UTC | 20,000 synthetic metadata events, 1,170 SQLite alerts; 5,649.91 events/s; processing+commit p50 0.0971 ms, p95 0.8416 ms | Source/model/script hashes match. Both core gates pass. Excludes capture, HTTP, SSE and browser. |
| `benchmarks/delivery_latest.json`, 1 Oct 12:11:03 UTC | 100/100 API/SQLite/SSE records; p50 129.06 ms, p95 240.27 ms, p99 251.66 ms | Source/model/script hashes match. Loopback p95<1,000 ms passes. Excludes Next.js proxy, capture and rendering. |
| `ml/encrypted_session_validation.json` | Controlled TP3/TN6/FP4/FN5; recall 37.5%, precision 42.86%, FPR 40% | Recorded runtime hashes match. Failed controlled quality gate; experimental, no independent reserved capture. |
| `ml/exfil_development.json` | Controlled TP4/TN2/FP4/FN1; recall 80%, precision 50%, FPR 66.67% | Recorded runtime hashes match. Failed intent-discrimination gate; byte accounting corrected. |
| `ml/dns_tunnel_candidate_validation.json` | Candidate validation TP5/TN5/FP0/FN0, query 5/12; rule-only baseline TP0/TN4/FP1/FN5 | Candidate/features/scenario hashes match, but report does not pin the full deployed hybrid pipeline. Development-only, candidate disabled; formal evaluation unavailable. |
| `ml/syn_flood_validation.json` | Controlled TP6/TN6/FP0/FN0, incremental and feature gates passed at recorded revision | Historical: extractor/rate/pipeline hashes differ. Retains the SYN functional decision; not newly validated on final source. |
| `ml/udp_flood_development.json`, `ml/spoofed_source_validation.json` | Controlled TP4/TN2/FP4/FN0; precision 50%, FPR 66.67% | Historical runtime revisions; failed quality/identifiability gates. Generic UDP DDOS heuristic active; spoof-specific predicate disabled. |
| `ml/c2_beacon_development.json` | Controlled TP3/TN6/FP2/FN3; recall 50%, precision 60%, FPR 25% | Historical extractor/pipeline revision; quality unresolved, periodic benign overlap. |
| `ml/recon_development.json` | Controlled TP4/TN3/FP3/FN1; recall 80%, precision 57.14%, FPR 50% | Historical extractor/pipeline revision; authorized-scanner false positives remain documented. |
| `ml/streaming_validation.json`, 29 Sep 13:19:51 UTC | Public-domain wrapper plus14 PCAPs/609,583 parsed IP packets | Historical: pipeline/extractor/rate hashes differ. Public replay sanity check, not final runtime or labelled tunnel recall. |
| `ml/runtime_evaluation.json`, 29 Sep 13:20:31 UTC | Frozen synthetic classifier F1 0.9894827640/0.9902547932 validation/test | Historical extractor/rate hashes; classifier-only, not hybrid or field accuracy. |
| `ml/evaluation.json` | Original synthetic classifier fit-time report | Historical; lacks current runtime provenance. Do not present as final deployed quality. |
| `ml/dga_v2_evaluation.json` | Inspected public-domain development recall 76.77%, FPR 1.68%; separate DNS FPR 2.34% | Candidate artifact matches, disabled; inspected cohorts influenced development. Recall/DNS gates failed. |
| `ml/dga_weighted_candidate_validation.json` | Validation recall 92.80%, precision 99.63%, FPR 1.82% | Candidate artifact/plan hashes preserved; validation only. Reserved domain and separate benign-DNS results null, promotion blocked. |
| `ml/public_*evaluation.json` | Separate completed-flow/domain research baselines and original PCAP replay | Historical experiments; none is the active runtime model. Failed public candidates remain inactive. |

The [audit JSON](verification/documentation-audit.json) contains report hashes,
recorded source mismatches and protected artifact/manifest hashes. Hash comparison
is provenance checking, not a new detection experiment.

## Historical public-domain and capture observations

The conservative-guard comparison reused six previously inspected DGA lists and
1,000 legitimate references: TP478/FN5518/FP0/TN1000, recall 7.97%, precision 100%,
reference FPR 0%. Original baseline TP5996/FN0/FP912/TN88 gave reference FPR 91.2%.
Real strings were wrapped in simulated tuples/times/sizes. Noise reduction came
with large recall loss; zero FPs on that list never certified deployment FPR.

The last saved public capture regression processed 609,583 IP packets from 14 files.
Its two benign references emitted **96** deduplicated alerts: DDOS55, DGA25, C2 13,
recon3. The earlier guard revision emitted97; the original baseline emitted1,671.
These are alert counts on publisher-designated references, not per-flow FPR.
Mixed attack-category captures lack joined trustworthy query/session labels, so
they cannot yield attack recall or precision. No formal tunnel alert was established.
These counts are historical and were not refreshed against current detectors.

All 14 captures have96-byte snaplen. Complete parsed DNS/53 names reached at most
36 characters, but clipped questions can be longer. Across the audit, attack-related
queries are mostly clipped before complete QNAME/QTYPE. UDP5355 is consistent with
LLMNR, not a new DNS attack input. The `heavy_text` port-header inventory counted
192,490 UDP5355 datagrams:124,085 clipped and68,405 complete questions (66,685 PTR,
1,508 ANY,212 A). See [visibility audit](DNS_TUNNELLING_VISIBILITY_AUDIT.md).

The archived [29 September narrative](history/STREAMING_VALIDATION_20260929.md)
preserves its original bytes. Statements saying “current” inside that archived
document refer to its historical revision only. Machine-readable results remain
unchanged. Demo provenance points to the archived narrative rather than silently
replacing its pinned evidence with this new index.

## Current implementation is not current accuracy

[Model/validation](MODEL_AND_VALIDATION.md) maps every threat to current features,
rules/models, data sources, recorded counts, false positives and limits. All seven
alert classes still function in the controlled [demo pack](FINAL_DEMO.md).
DGA weighted validation success and tunnel development success do not justify
promotion without the untouched final sets and unchanged gates. Most intent-based
detectors fail matched benign controls; this remains an unresolved deliverable risk.

The latest completed full working-tree suite was 223 tests in demo preparation; the later
initial clean-checkout attempt reported 219 passed/4 failed due packaging/provenance.
Setup corrections and two new packaging tests were added, but that full clean run
was not repeated before the owner selected this documentation task. The earlier
UI report records20/20 production browser checks and TypeScript/build success for
that run. None is labelled a newly completed clean-install check.

For this documentation audit, demo preflight and all 15 targeted demo regressions
passed after the historical narrative was archived. Six model checksums, eight
dataset/protocol manifest hashes and both latest benchmark provenance sets were
verified; 72 local Markdown links resolved. No full backend suite, frontend build
or performance measurement was rerun. Individual detector narratives retain their
original revision and frozen criteria: “current” within a historical narrative
means current at that recorded revision, as classified in the table above.

## Reproduction boundaries

Follow README for installation, tests, demo preflight and the two benchmark commands.
`python -m datasets.validate_streaming` requires the locally downloaded public
inputs and overwrites its report. `python -m ml.train --evaluate-only` overwrites the
classifier report; regular `ml.train` refits the frozen model. Do not run either
as a documentation refresh or replace missing final evidence with inspected data.

No payload decryption, external reputation/DNS query, source probe, active address
verification or inline response is implemented. See [expected solution](EXPECTED_SOLUTION.md)
and [completion plan](COMPLETION_PLAN.md) for the distinction between working
prototype infrastructure and unresolved detection-quality acceptance.

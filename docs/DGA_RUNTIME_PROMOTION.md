# DGA runtime promotion decision — 2 October 2026

**DGA remains unresolved. Runtime promotion is blocked; no runtime model change.**
The latest OOF candidate has not passed all four frozen final gates. Development
validation passes three domain gates, but independent reserved domain evaluation
and separate benign-DNS evaluation are unavailable. Unmeasured results cannot be
treated as passing. This is missing acceptance evidence, not a newly observed
numerical model failure.

## Evidence inspected and verified

- [Frozen evaluation protocol](DGA_EVALUATION_PROTOCOL.md) and its exposure supplement.
- [OOF experiment plan](../data/dga_oof_candidate_plan.json), SHA256
  `2c71a2c545b8f86dde3da1d0c8b262195e8663abb3e1898281f7060e05791461`.
- [OOF validation report](../ml/dga_oof_candidate_validation.json), SHA256
  `892563c02060825d41e70bdff287699c95ea6c7bad35dff6382cff02e58f12ec`.
- [OOF artifact](../ml/dga_oof_candidate.json) and matching checksum, SHA256
  `266b80bc7edac63dda815b61ef6ef162d2af9b919e70bfa168958133431b730b`.
- Portable scorer activation logic, pipeline's conservative fallback and existing
  DGA/completion documentation. All 29 experiment-protected input/artifact/report/
  runtime/history hashes still match the preregistered plan.

Report-to-plan/artifact hashes, threshold 0.9 and unchanged final gates match.
The report explicitly records `blocked_missing_reserved_evaluation`, with
`reserved_evaluation=null` and `separate_benign_dns_fpr=null`.
`data/dga_reserved_materialization.json` is absent; only existence was checked.
No reserved examples, scores or outcomes were inspected or fabricated.

## Frozen gates and exact scope

| Requirement | Existing development validation | Required independent final evaluation |
| --- | --- | --- |
| Recall >=80% | 90.065%, pass | Unmeasured |
| Precision >=95% | 99.733%, pass | Unmeasured |
| Domain FPR <=2% | 1.2667%, pass | Unmeasured |
| Separate benign-DNS FPR <=2% | Not measured in this training run | Unmeasured |

Validation TP/TN/FP/FN are **72,052 / 15,043 / 193 / 7,948**, F1 **94.653%**.
These unchanged results use previously inspected development domains and do not
represent production generalization or final acceptance. Historical comparison
and DNS references cannot substitute for the missing reserved sources. No gate,
threshold, feature, partition or artifact flag was changed.

## Runtime state and checks performed in this task

`ml.dga.ARTIFACT` still selects `ml/dga_v2.json`. Default public-model loading
remains disabled, so `detection.pipeline.Pipeline` retains the existing
`conservative_rule` fallback alongside the guarded synthetic DGA classifier.
The OOF artifact is an inactive development output and is not selected by runtime.

Hash-verified loading confirmed `enabled=false` for the original public, weighted
and OOF artifacts. Each `predict('xqjmtvkp.example')` returns `None` while disabled.
Primary synthetic artifact, runtime code, alert contract, supporting evidence,
candidate artifacts and analyst history remain byte-identical to the protected
baseline. No DNS-tunnelling or other detector code was changed.

This task changes documentation only. No regression tests were added because no
executable behavior or bug was changed. Integrity/disabled-state checks passed;
the full suite, replay regressions, frontend build and runtime-cost benchmark
were not rerun because the user's non-passing promotion branch requires stopping
without integration. The preceding training task's **66 DGA / 249 full backend**
test results are historical evidence, not new test results for this task.

## Definition of Done and next step

The runtime-promotion decision task passes its conditional Definition of Done:
eligibility was verified, DGA is explicitly unresolved, and the candidate remains
safely disabled with runtime unchanged. DGA final quality acceptance does **not**
pass. Freeze the unchanged artifacts, behavior, tests, prior metrics and reports;
do not refit, retune or integrate during this task.

**Exactly next for DGA:** separately materialize eligible untouched reserved
algorithm/domain/benign-DNS sources, verify provenance, algorithm aliases,
canonical-label disjointness, counts and hashes, then freeze the materialization
manifest. Evaluate the already frozen candidate once without tuning before any
later runtime promotion. No new experiment or future phase starts automatically.

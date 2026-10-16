# C2 diagnostic scope freeze

16 October 2026; baseline bdffcf0. Development-only observability diagnosis.

Inputs: the fourteen already exposed cases from validate_c2_beacon.py and the
release-audit/c2_beacon_development.json plus the 7 October failure attribution.
No acquisition, fresh holdout, reserve, training, ablation or threshold search.
Preserve existing gates: recall >=80%, precision >=95%, benign-scenario FPR <=2%,
early alerts with jitter/non-demo interval/small rotation coverage.

Reproduce only the two recorded false positives up to their first C2 alert;
require exact event, evidence and rule/model attribution. Retain all historical
verdicts; do not rescore positives or compute refreshed accuracy.
For the existing cases only, inspect causal feature histories without prediction;
verify saved maxima/final snapshots and compare paired opposite-label scenarios
with the same timing generator. Distinguish serialized TrafficEvent equality,
complete runtime-feature equality, GNB-vector equality and C2 rule equality.
Labels/names are annotations, never predictors. Check source/model/stream hashes.
Do not access or write analyst persistence. Keep runtime/model/generator frozen.

DoD: reproducible C2-only diagnostic with tested scope/integrity guards, FP/FN
breakdown, visibility/feature diagnosis and ONE smallest next experiment, not its
implementation. Report historical quality failure accurately. Stop at this decision.

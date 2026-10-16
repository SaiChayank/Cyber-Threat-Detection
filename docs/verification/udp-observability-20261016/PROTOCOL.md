# T20 — UDP observability decision

16 October 2026. Baseline commit `8950e0b`. Diagnostic only on the ten already
exposed `datasets.validate_udp_flood.CASES`. Inspect frozen UDP validation and
baseline failure reports, runtime feature/rule/parser/model code before changes.

Use the existing failure-analysis implementation with a UDP-only selection. Check
the saved generator, labels, event counts, first-FP alert evidence and actual
rule/model attribution. Compare opposite-label collisions in full TrafficEvent
metadata, frozen model vectors and complete causal extractor dictionaries.
Distinguish normalized metadata from raw packet bytes and lab labels from intent.

No new scenarios, counterfactual scoring, threshold search, training, promotion,
reserved construction/inspection, source lookup, packets sent or database writes.
Keep every hard negative. Do not invoke the UDP validator's report-writing main
function or the multi-detector diagnostic mode. Do not repeat encrypted ablation.

Frozen quality gate remains recall >=80%, precision >=95%, benign FPR <=2%,
existing timing/accounting/coverage checks; no quality improvement claimed here.
Run UDP/diagnostic unit tests, preserve old evidence/artifact bytes, record the
smallest justified next experiment and its non-regression criteria, or an explicit
visibility/data blocker. Stop after the decision; commit the verified task.

# Encrypted fingerprint-risk sensitivity — 7 October 2026

**Definition of Done: PASSED for the offline experiment. Runtime adoption:
REJECTED; no candidate trained or promoted.** Zeroing fingerprint risk does not
resolve encrypted-indicator quality, and the unchanged fingerprint rule still
matches shared-fingerprint benign traffic.

## Frozen method and inspected baseline

Inspected the existing encrypted generator/report/protocol, current Pipeline and
extractor, GNB/model source, frozen feature contract, preceding failure analysis
and encrypted visibility tests. The [protocol](verification/encrypted-fingerprint-sensitivity-20261007/PROTOCOL.md)
was recorded before running predictions. Sources, scenario order/labels/stream
hashes, all 20 features/order and original model integrity were verified.

Model SHA256 remains
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
Only the existing 18 previously inspected development scenarios are used: 360
events, eight positive and ten benign scenarios. No reserved/public dataset is
newly evaluated, and no fitting, tuning or threshold change occurs.

The actual Pipeline produces causal features and its observed GNB prediction.
A separate copied model input sets only `fingerprint_risk=0` and calls that same
frozen GNB. **Only the observed prediction returns to Pipeline.** The observed
features, raw fingerprints/events and rule inputs remain intact. Both top labels
and top-class posteriors are retained at every event; these are not calibrated
maliciousness probabilities or the complete per-class posterior distribution.

The 80 lab-fingerprint events change one input bit; all other 280 input pairs and
predictions match exactly. Twenty-eight top labels change, and thresholded target
hit events fall from 68 to 32. A label can stay the same while its top posterior
crosses the unchanged 0.8 cutoff, so those two change counts need not match.

## Model-only seen-scenario sensitivity

Positive target hit before final event counts as TP; otherwise FN. Any target
model hit on a benign scenario counts as FP. No counterfactual alert is emitted.

| Metric | Observed model | Counterfactual risk zero |
| --- | ---: | ---: |
| TP / TN / FP / FN | 3 / 6 / 4 / 5 | 2 / 7 / 3 / 6 |
| Precision | 42.86% | 40.00% |
| Recall | 37.50% | 25.00% |
| F1 | 40.00% | 30.77% |
| Benign-scenario FPR | 40.00% | 30.00% |

One model-only benign false positive disappears, at the cost of one positive
scenario. Precision, recall and F1 worsen; residual FPR remains high. These are
paired sensitivity results on seen controlled data, not independent accuracy.
The diagnostic does not become a promotable candidate because FPR decreased.
Compared with existing recall>=80%, precision>=95%, FPR<=2% criteria, all three
counterfactual values are still inadequate. The gates were not changed or applied
as a fresh reserved promotion evaluation.

## Scenario effects and timing

| Scenario | Model target-hit events, before → after | First model hit, before → after | Finding |
| --- | ---: | --- | --- |
| `lab_tls_stable` | 17 → 0 | event 4 / 7.5s → absent | Positive TP becomes FN; strong fingerprint shortcut dependency. |
| `lab_tls_bursty` | 18 → 16 | event 3 / 3s → event 5 / 8s | Remains TP; timing/size features also contribute. |
| `browser_shared_ja3` | 19 → 4 | event 2 / 2.1s → event 15 / 27s | Remains FP despite removing the fingerprint signal. |
| `update_shared_ja3` | 2 → 0 | event 1 / 0s → absent | Model-only FP becomes TN; observed rule still fires at event 1. |

All fourteen zero-risk scenarios are exact controls. The novel/no-Hello/stable
QUIC positives remain missed. `quic_variable` retains its target hits, as do
`browser_tls` and `ordinary_encrypted_app`; their identical 20-feature sequences
prevent this one-bit change from separating purpose. No raw QUIC fingerprint or
decrypted payload was added.

## Original alert path and failure interpretation

All 18 original scenario verdicts, first-alert positions/timing/evidence and saved
model/rule event-hit counts reproduce. Actual hybrid counts stay **TP3/TN6/FP4/FN5**.
The observed fingerprint rule still matches 80 events across two lab-positive and
two shared-fingerprint benign scenarios; deduplication suppresses repeated alerts.
Counterfactual model decisions do not bypass that rule or enter persistence/SSE.
This is not a measurement of a counterfactual full-hybrid implementation.

Root cause is mixed: the fingerprint is a learned shortcut and a sufficient
rule condition, while non-fingerprint timing/size overlap independently produces
false positives and misses. Missing/limited handshake visibility and inadequate
label/feature separability remain constraints. Replacing that bit with zero cannot
manufacture unseen malware evidence. No failed/unassessed research candidate is
enabled; the legacy active baseline remains unchanged with disclosed limitations.

## Files, tests and freeze

Added `datasets/encrypted_fingerprint_sensitivity.py`,
`tests/test_encrypted_fingerprint_sensitivity.py`, this document and dated
protocol/report/evidence. Model documentation and completion plan link the result.

Twelve new regression cases cover one-bit copy/nonmutation, identical negative
controls, inconsistent predictor detection, binary representation, unchanged 0.8
cutoff, early-positive/any-benign metric semantics, immutable original alert path
on a lost positive and an eliminated model FP, novel controls and changed-stream
rejection. **26 targeted tests passed**, including encrypted visibility and prior
baseline-analysis regressions. Shared runtime/frontend code did not change, so
full backend/build was not rerun; prior recovery recheck passed 268 backend tests,
TypeScript and production build. No performance benchmark is refreshed here.

The [report](verification/encrypted-fingerprint-sensitivity-20261007/report.json)
contains all event-level observed/counterfactual comparisons and provenance;
[test log](verification/encrypted-fingerprint-sensitivity-20261007/tests.log)
records the targeted checks. Freeze this experiment, tests, protocol, artifact
reference, result and limitations. Preserve previous reports and datasets.

## Exactly next

Recommend **one encrypted development-data feasibility/visibility check**: inspect
only existing permitted, already-development datasets/captures for trustworthy
encrypted-session labels and actually observable ClientHello cipher/extension
metadata. Record coverage and possible family/time separation before deciding
whether a richer causal representation is testable. Do not inspect reserved data,
invent labels, extract raw QUIC fingerprints, train or change a detector.
That next task has not started. Further model changes need usable data rather
than another threshold adjustment on this contradictory synthetic matrix.

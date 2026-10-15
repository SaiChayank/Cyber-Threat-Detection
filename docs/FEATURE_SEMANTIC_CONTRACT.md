# Offline feature-semantic contract — 7 October 2026

**Definition of Done: PASSED for the offline tool. Historical classifier
compatibility: FAIL (known drift remains unresolved).** No model-quality gate is
newly passed, and no detector/model is trained, changed, disabled or activated.

## Finding and scope

Inspected the frozen GNB artifact/loader, current trainer/extractor/rate windows,
event schema, runtime Pipeline, pinned historical source, preceding
[feature-parity diagnosis](FEATURE_PARITY_DIAGNOSTIC.md), tests and completion plan.
The runtime loader checks raw model checksum and names/order, but has no semantic
version. That permits definitions to drift while the same 20 names still load.

The offline manifest records all 20 definitions, transform, historical Git
reference, raw model SHA256, 11 current source text hashes, history/window/weighting
and missing-value semantics. It freezes known historical differences rather than
declaring corrected current accounting compatible with the historical model.
Model hash remains
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.

| Check | Before | After |
| --- | --- | --- |
| Names/order and model checksum | Existing runtime checks | Preserved; offline checks also pin order and transform |
| Window/rate/weighting/missing values | Not independently versioned | Checksummed offline definitions and behavioral regressions |
| Current code conformance | Not independently checked by a semantic preflight | PASS on recorded definitions and controlled probes |
| Historical compatibility | Same names could obscure known drift | FAIL explicitly: packet_rate, byte_rate, source_entropy, byte_ratio |
| Prediction accuracy / runtime cost | Prior scoped evidence only | Not measured or changed in this task |

## Reproduce and interpret

```powershell
.venv/Scripts/python.exe -B -m datasets.check_feature_contract
.venv/Scripts/python.exe -B -m datasets.check_feature_contract --output semantic-report.json
.venv/Scripts/python.exe -B -m pytest tests/test_feature_semantic_contract.py tests/test_feature_parity_diagnostic.py tests/test_rate_window.py -q -p no:cacheprovider
```

Exit **1 is expected today**: current conformance PASS, historical compatibility
FAIL. Exit 0 requires both to pass. Unexpected source/behavior/model drift,
integrity failure or unavailable history gives exit 2 and compatibility UNVERIFIED.
The check is not connected to backend startup and does not silently change runtime
model activation. An existing output report is never overwritten.

The CLI requires the original commit
`8c1b7cc70d3318a28f107fa2ca9f292e95e9a583` in local Git history. It does not fetch
history or fall back to a different reference. Unit tests use the already pinned
historical-source fixture and can run in a source archive/shallow snapshot.
Model hash is raw bytes; manifest/source text hashes normalize CRLF to LF for
Windows/Linux checkout consistency. The contract sidecar is an integrity check,
not a signature or permission to edit both files without review.

## Tests, evidence and limits

Twenty new cases check baseline conformance, known nonzero compatibility result,
rate/entropy/reverse semantics changing with unchanged feature names, transform
and order changes, changed model despite a matching replacement sidecar, source
pins, CRLF, null/bool/nonfinite comparisons, missing history and report preservation.
The combined semantic/diagnostic/rate suite passes **31 tests**. It uses only
controlled metadata, no training/validation/reserved dataset rows, no predictions
and no fitting. Controlled expiry, source-overflow recovery, late-drop, peer
size/SYN/history and reverse-data cases extend the existing diagnostic probes.

Evidence: [final report](verification/feature-semantic-contract-20261007/report-final.json),
[test log](verification/feature-semantic-contract-20261007/tests-final.log) and
[acceptance criteria](verification/feature-semantic-contract-20261007/ACCEPTANCE.md).
The preceding full backend/build evidence remains the recovery recheck (268 tests,
TypeScript/build passed); shared runtime and frontend behavior did not change here.
Final integrity checks confirm **81 protected files unchanged**, including the
frozen artifacts, runtime code, prior diagnostic/fixture, analyst history and Git
index. [Freeze record](verification/feature-semantic-contract-20261007/freeze.json)
pins the new tool/manifest/tests/report and records the current conformance decision.

Freeze this version, definitions, tests and report. Finite probes do not prove
semantic equivalence or generalization. Source pins deliberately require review
even for a comment-only change. The original reference's matching model bytes do
not independently establish the exact training execution. Known synthetic
fingerprint/reverse-availability shortcuts, granularity shift, bounded legacy ML
egress history and unresolved detector quality remain disclosed. No corrected
causal accounting was reverted to reproduce historical bugs.

## Files and next task

Added `datasets/check_feature_contract.py`,
`tests/test_feature_semantic_contract.py`,
`data/feature_semantic_contract.json` and its `.sha256`, this document and dated
evidence. README, model documentation and completion plan link the offline check.
The previous diagnostic implementation and runtime/model/raw-data/history files
are unchanged.

Next: **failure analysis of the active baseline's already evaluated benign hard
controls**, separating rule triggers from frozen-model contributions. Identify
affected scenarios and recommend one smallest experiment; do not implement it,
train, tune or inspect reserved evaluation data. That next task has not started.

# DGA training-only OOF candidate — 2 October 2026

**Promotion decision: BLOCKED — missing independent reserved evaluation.**
One candidate was trained. It passed the three development-domain validation
gates but has not passed all four final promotion gates. It remains disabled,
is not integrated into the runtime pipeline, and is not an approved model.

## Inspected baseline and preregistration

Inspected the [diagnostic](DGA_DIAGNOSTIC.md), [frozen evaluation design](DGA_EVALUATION_PROTOCOL.md),
[feature/rule comparison](DGA_FEATURE_VALIDATION.md), source/exposure manifests,
weighted and original candidate trainers/reports, portable scorer, active DGA
guard, pipeline and tests. The measured risk was that the booster received the
base encoder's in-sample training logits, while runtime/validation logits were
out of sample. This run tests that one training-path hypothesis; it changes no
detector or lexical feature.

[Frozen experiment plan](../data/dga_oof_candidate_plan.json), SHA256
`2c71a2c545b8f86dde3da1d0c8b262195e8663abb3e1898281f7060e05791461`,
was saved before any fitting or new scoring. It pins 29 existing sources,
artifacts, reports, runtime/training source files and analyst history files, plus
the exact training/validation row digests. The parent protocol and earlier
candidate plans/reports remain unchanged.

Training: **69,993 DGA + 67,715 benign first labels**. Validation: **80,000 DGA +
15,236 benign first labels**. These are previously inspected development sources,
not contemporary production ground truth or independent final evaluation.

## Exactly one intervention

Use three deterministic training-only folds. Assign positive rows by SHA256 of
`PS26145-DGA-OOF-v1:family:<family-prefix>` modulo three; use the family prefix
before the first underscore so related named variants stay together. Assign
benign rows by SHA256 of `PS26145-DGA-OOF-v1:benign:<canonical-first-label>` modulo
three. Family labels affect partitioning/reporting only, never prediction.

| Held fold | DGA rows | Benign rows |
| --- | ---: | ---: |
| 0 | 27,995 | 22,726 |
| 1 | 12,000 | 22,610 |
| 2 | 29,998 | 22,379 |

Each fold independently fits vocabulary, IDF, numeric scaler and logistic encoder
on the other two training folds, then scores its held training rows exactly once.
The one boosted stack fits these OOF logits plus the ten raw runtime-compatible
numeric features. Refit the final base encoder once on all training rows for
portable export. Three temporary base fits and a final refit are components of
one candidate, not four candidate experiments. No validation rows fit any stage.

Preserve first-label 2/3-gram TF-IDF and the exact `ml.dga.lexical_features` numeric
definitions: log length, entropy, digit/vowel/hyphen/unique ratios, maximum
consonant/digit runs, digit transitions and repeat ratio. Hyperparameters remain
the original `C=1`, liblinear, balanced logistic class weights, 300 iterations,
seed 26145; booster 100 trees, depth 3, learning rate 0.08, minimum leaf 1000.
No additional benign weighting is applied. The threshold is frozen at **0.9**;
there was no threshold grid search or rescue after observing validation results.

No dataset name, family, source address, filename or scenario ID is a predictor.
No suffix, external lookup, payload decryption or future query is used. Prefix
grouping does not prove all algorithm aliases are independent; that remains a
reserved-source provenance requirement.

## Validation result and comparisons

[Machine-readable validation report](../ml/dga_oof_candidate_validation.json)
SHA256 at measurement:
`892563c02060825d41e70bdff287699c95ea6c7bad35dff6382cff02e58f12ec`.
It records all metrics, per-family recall, fold provenance, error analysis,
baseline/report hashes, protected before/after hashes and final gates.

| Configuration | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Effective deployed synthetic DGA path / active rule | 19,374 | 15,212 | 24 | 60,626 | 99.88% | 24.22% | 38.98% | 0.16% |
| Validation-only rule baseline | 45,255 | 15,168 | 68 | 34,745 | 99.85% | 56.57% | 72.22% | 0.45% |
| Original public candidate, threshold 0.9 | 73,577 | 14,968 | 268 | 6,423 | 99.64% | 91.97% | 95.65% | 1.76% |
| One OOF candidate, threshold 0.9 | 72,052 | 15,043 | 193 | 7,948 | 99.73% | 90.07% | 94.65% | 1.27% |

Baselines reuse the hash-pinned fresh feature/rule validation report; they were
not refitted or newly scored in this task. The effective deployed DGA path is
the mandatory conservative guard: its match emits a rule/hybrid DGA alert, and
the pipeline rejects unguarded synthetic DGA predictions while the public model
is disabled. This is a domain-decision comparison without deduplication effects,
not standalone synthetic posterior accuracy or a real-time capture benchmark.

OOF false positives decreased by **75 (27.99%)** relative to the original public
candidate at the same threshold. Recall decreased by **1.90625 percentage points**
and false negatives increased by 1,525. This is a validation trade-off, not proof
that the stacking risk caused every earlier failure or that generalization is fixed.

| Validation DGA family | Original recall | OOF recall |
| --- | ---: | ---: |
| cryptolocker | 97.87% | 97.26% |
| fobber_v1 | 99.89% | 99.87% |
| fobber_v2 | 87.44% | 83.00% |
| locky | 88.04% | 85.32% |
| murofet_v1 | 100.00% | 100.00% |
| murofet_v2 | 99.58% | 99.46% |
| murofet_v3 | 100.00% | 100.00% |
| proslikefan | 62.95% | 55.61% |

Legitimate FP shape counts: long alphabetic **132**, short alphabetic **38**,
mixed alphanumeric **13**, hyphenated **8**, hexadecimal-shaped **2**, digit-only
**0**. Short alphabetic positives account for **7,518/7,948** misses. Per-family
FN counts are proslikefan **4,439**, fobber_v2 **1,700**, locky **1,468**,
cryptolocker **274**, murofet_v2 **54**, fobber_v1 **13**, and zero for murofet_v1/v3.
Long legitimate names and pronounceable/short DGA coverage therefore remain
limitations, even though the aggregate validation domain gates pass.

## Portable artifact and integrity

Development-only [artifact](../ml/dga_oof_candidate.json), 2,349,407 bytes:

`266b80bc7edac63dda815b61ef6ef162d2af9b919e70bfa168958133431b730b`

Its [.sha256 sidecar](../ml/dga_oof_candidate.sha256) covers the exact compact JSON
bytes; both files omit trailing newlines to avoid Windows checkout conversion.
`runtime_enabled=false`. Runtime representation remains the existing bounded
standard-library scorer; there is no sklearn dependency in deployed inference,
pickle, new framework, service or database. No runtime artifact was replaced.

Independent sklearn-versus-portable validation checks used **201** saved reference
vectors with maximum absolute score error **1.11e-16**, below the frozen **1e-10**
tolerance. Reference vectors are validation only, never reserved data. Existing
raw sources, deployed and disabled artifacts, alert history and prior reports
retain their hashes.

## Promotion decision and stop

| Frozen gate | Development validation | Independent reserved evaluation |
| --- | --- | --- |
| Recall >=80% | Pass: 90.065% | Unmeasured |
| Precision >=95% | Pass: 99.733% | Unmeasured |
| Domain FPR <=2% | Pass: 1.2667% | Unmeasured |
| Separate benign-DNS FPR <=2% | Not evaluated here | Unmeasured |

`data/dga_reserved_materialization.json` does not exist. The required unseen
three-algorithm positive set, five-stratum legitimate set and separately sourced
benign-DNS reference cannot be evaluated once because they are not materialized
and verified. The previously inspected comparison and second DNS capture cannot
substitute for them. Do not describe this missing evaluation as a numerical
failure or an all-gates pass. **Promotion is blocked and the candidate stays
disabled.** No threshold/gate was lowered and no reserved example, outcome or
score was inspected. No new data acquisition or second experiment occurred.

## Reproduction, regression and freeze

The single training command was:

```powershell
.venv/Scripts/python.exe -m datasets.train_dga_candidate --oof
```

Installed offline training environment: Python **3.13.5**, scikit-learn **1.9.1**,
NumPy **2.5.3**, SciPy **1.18.1**. No dependencies were added. Both trainer modes
now reject existing outputs before fitting, and exclusive file creation also
prevents clobbering files created during a run. Repeating the command in this
workspace intentionally refuses to retrain/overwrite the frozen result. To
reproduce fitting, use a disposable work copy with the four new OOF output files
absent and all hash-pinned development sources available; preserve the reference
artifact/report in the main repository. Do not silently delete prior results.

Tests cover frozen feature/gate/plan contracts, deterministic family grouping,
benign identity grouping, exact held-row coverage and isolation, finite/complete
OOF scores, evidence overwrite prevention, failed-gate wording and portable
reference parity. Targeted DGA tests: **66 passed**. Full backend suite:
**249 passed** in 48.18 seconds, with one existing FastAPI/Starlette HTTPX
deprecation warning. No unrelated detector regression was observed.
No runtime/shared contract or frontend behavior was
changed, so no frontend build result is claimed for this training-only task.

Freeze this candidate's code behavior, feature contract, fixed threshold,
artifact/version/hash, reference vectors, tests, validation metrics and known
limitations. Do not optimize or refit it during another completed-feature task.
The training/validation/export portion passes; the requested complete final-gate
Definition of Done is **blocked**, not passed.

**Exactly next:** separately materialize eligible independent reserved sources,
perform integrity/algorithm-alias/label-overlap/benign-stratum checks, and freeze
that manifest. Then evaluate this already frozen candidate once without tuning.
If it fails any final gate, leave it disabled and perform failure analysis only;
if it passes all four, a later explicit runtime-promotion task is required.

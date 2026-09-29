# One frozen DGA candidate — training/validation result

The single preregistered choice is recorded in
[`data/dga_candidate_plan.json`](../data/dga_candidate_plan.json) and protected by
its `.sha256` sidecar. It was frozen **before fitting or scoring validation**.
`python -m datasets.train_dga_candidate` fits only the existing 69,993 positive
and 67,715 benign training first labels, selects a threshold only on the existing
80,000 positive and 15,236 benign validation labels, and writes a **disabled**
separate artifact plus
[`ml/dga_weighted_candidate_validation.json`](../ml/dga_weighted_candidate_validation.json).
It never scores the prior comparison families, the inspected second DNS capture,
or any reserved evaluation set. The existing `ml/dga_v2.json`, synthetic model
and active rule remain byte-identical and active/inactive as before.

## Frozen candidate

The previous diagnostic found that long alphabetic legitimate labels dominate
false positives. This one candidate gives **3× additional fit weight** to
training benign first labels with at least 12 alphabetic characters and 1× to
all other training labels. The same weights enter the base logistic encoder and
the boosted trees. No other model hyperparameter, feature, data split or gate
was changed. The predictor sees only first-label character bigrams/trigrams and
the same ten `ml.dga.lexical_features` fields used by portable runtime inference:
length, entropy, digit/vowel/hyphen ratios, unique-character ratio, consonant
and digit runs, digit transitions, and adjacent repeats. Family names, source
identifiers, filenames, addresses, scenario IDs, suffixes and future events are
not predictors. Weights use the training label's visible shape and supervised
class only; family is retained solely for partitioning and metric reporting.

The threshold came from the predeclared grid and validation-only rule. **0.85**
had the highest validation recall while meeting recall >=80%, precision >=95%
and FPR <=2%. Keeping that choice prevents a later false-positive-driven
threshold change after seeing a final cohort. The candidate JSON is 2,349,090
bytes, has SHA256 `e81821f753d1e1b71fb5a08ff446467165941db996929767edec008c01c130ca`,
and has `runtime_enabled=false`. Its standard-library portable scorer matched
sklearn on 201 validation samples with maximum absolute error **2.22e-16**.

## Validation comparison

| Configuration | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Deployed synthetic DGA alert path / old guard | 19,374 | 15,212 | 24 | 60,626 | 99.88% | 24.22% | 38.98% | 0.16% |
| Validation-only rule variant | 45,255 | 15,168 | 68 | 34,745 | 99.85% | 56.57% | 72.22% | 0.45% |
| Existing disabled public candidate | 73,577 | 14,968 | 268 | 6,423 | 99.64% | 91.97% | 95.65% | 1.76% |
| **New disabled weighted candidate** | **74,242** | **14,958** | **278** | **5,758** | **99.63%** | **92.80%** | **96.09%** | **1.82%** |

With the public candidate disabled, the production pipeline cannot issue a DGA
alert from its synthetic Gaussian NB posterior alone: the conservative lexical
guard is required, and it also triggers independently. Therefore the **effective
deployed DGA decision on these public-domain strings equals the old rule row**.
Raw synthetic-model accuracy on simulated traffic would not measure public DGA
generalization.

| Validation family | Existing public candidate recall | New candidate recall |
| --- | ---: | ---: |
| cryptolocker | 97.87% | 97.23% |
| fobber_v1 | 99.89% | 99.73% |
| fobber_v2 | 87.44% | 89.17% |
| locky | 88.04% | 89.48% |
| murofet_v1 | 100.00% | 100.00% |
| murofet_v2 | 99.58% | 99.35% |
| murofet_v3 | 100.00% | 100.00% |
| proslikefan | 62.95% | 67.46% |

The single weighting hypothesis **did not reduce validation false positives**:
FP rose from 268 to 278 at the preregistered selected thresholds, while recall
rose by 0.83 percentage points. It is a trade-off, not a demonstrated correction
of long-alphabetic false alarms. Family recall remains uneven, especially
proslikefan. Validation precision is measured on a positive-heavy reference
set, not on production traffic.

## Promotion decision: blocked, candidate disabled

The candidate passed the three *development validation* gates. It has **not
passed all four final gates**: the independent three-algorithm/five-benign-stratum
domain set and separate benign-DNS set required by the frozen
[evaluation protocol](DGA_EVALUATION_PROTOCOL.md) have not been acquired or
materialized. Final recall, precision, domain FPR and separate DNS FPR are
therefore **unmeasured**, not assumed to pass. The already-inspected comparison
and DNS references cannot be substituted for a fresh final set. The earlier
public candidate failed those inspected cohorts, but this new candidate was not
scored on them in this task. No gate or threshold was lowered, and no runtime
integration or model promotion occurred.

The exact next step is to materialize and hash the independent reserved sources,
verify algorithm and scored-label disjointness plus all benign strata, freeze
that materialization manifest, and then score this already-frozen candidate
**once**. If any of the four gates fail, keep it disabled and record the failed
counts. If all pass, a separate runtime-promotion task may integrate it.

# DGA diagnostic only

Scope frozen before the diagnostic run: inspect the existing active guard and
disabled candidate on already-inspected local sources. No new evaluation dataset,
training, threshold search, model promotion, runtime changes or source queries.

The existing threshold remains 0.9. Project gates remain recall >=80%, precision
>=95%, domain FPR <=2% and separate benign-DNS FPR <=2%. Diagnostic acceptance is
separate: reproduce existing confusion counts, break down FP/FN and feature patterns,
audit partition overlap, identify representation/shortcut risks, and recommend the
smallest next experiment. Frozen artifacts and raw data must remain untouched.

`python -m datasets.diagnose_dga` uses the fitted portable scorer and existing split
loader. It writes `ml/dga_diagnostic.json` only. The private offline score method is
used because `predict()` correctly abstains while the candidate is disabled. This
does not activate it in the pipeline or emit/store dashboard alerts.

Feature bins and mutually exclusive syntax groups are fixed in the diagnostic
script before scoring. They describe label shapes, not inferred service roles or
maliciousness. Feature/error associations are not causal importance measurements.

## Frozen result reproduced

The disabled candidate still scores at **0.9**. The diagnostic reproduced the
saved counts exactly; it did not fit, export or activate a model.

| Existing cohort | TP | FN | FP | TN | Recall | Precision | Benign-label FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | 73,577 | 6,423 | 268 | 14,968 | 91.97% | 99.64% | 1.76% |
| Domain comparison | 46,503 | 14,074 | 251 | 14,659 | 76.77% | 99.46% | 1.68% |
| Second DNS reference | — | — | 275 | 11,456 | — | — | 2.34% |

The promotion gate remains **failed**: comparison recall is below 80% and the
second DNS-reference FPR exceeds 2%. Precision and domain-comparison FPR pass on
these reference sets, but the class balance makes their precision unsuitable as
a live-traffic estimate. Scores are uncalibrated. Full fixed-bin counts, feature
profiles, per-family examples and source hashes are in `ml/dga_diagnostic.json`.

## False negatives: family and representation

| Comparison family | Missed / evaluated | Recall | Distinguishing observation |
| --- | ---: | ---: | --- |
| symmi | 4,275 / 10,000 | 57.25% | Short, vowel-rich labels; missed median length 10, score 0.543. |
| ccleaner | 4,133 / 10,000 | 58.67% | All labels are hexadecimal-shaped; missed labels have longer digit runs. |
| kraken_v1 | 3,355 / 9,994 | 66.43% | Missed median length 7, score 0.570. |
| kraken_v2 | 1,676 / 8,080 | 79.26% | Missed median length 8, score 0.688. |
| bedep | 314 / 10,000 | 96.86% | Smaller contribution. |
| sisron | 269 / 2,503 | 89.25% | Only 2,503 distinct scored first labels. |
| chinad | 52 / 10,000 | 99.48% | Smaller contribution. |

The first four families account for **13,439 / 14,074 misses (95.49%)**. In
validation, proslikefan accounts for 3,705 / 6,423 misses (57.68%); its recall is
62.95%. The comparison misses include **7,957 short alphabetic** and **4,133
hexadecimal-shaped** first labels. Misses have median length 10 and mean entropy
2.86 versus 13 and 3.22 for detections. Their median score is 0.542, well below
0.9; a small threshold adjustment cannot explain or safely resolve the gap.

These are *reference-family* labels, not verified malicious flows. The comparison
split has no unseen word-based family group, so this breakdown does not establish
how the model performs on contemporary word-based DGAs.

## False positives: legitimate-reference shapes

Groups below are mutually exclusive descriptions of scored **first-label syntax**.
They do not assert what service a name belongs to, or that its publisher label is
infallible. Long alphabetic means at least 12 characters.

| Shape | Domain comparison FP / benign labels | Second DNS FP / benign labels |
| --- | ---: | ---: |
| Long alphabetic | 142 / 2,654 (5.35%) | 165 / 2,444 (6.75%) |
| Short alphabetic | 67 / 9,407 (0.71%) | 59 / 7,034 (0.84%) |
| Hyphenated | 33 / 1,438 (2.29%) | 41 / 1,440 (2.85%) |
| Mixed alphanumeric | 6 / 1,330 (0.45%) | 8 / 792 (1.01%) |
| Hexadecimal-shaped | 3 / 4 | 2 / 2 |
| Digits only | 0 / 77 | 0 / 19 |

The hexadecimal benign denominators are too small for generalization. Long and
short alphabetic labels together contribute 209/251 comparison FPs and 224/275
DNS-reference FPs. Examples include `vaxvacationaccess.com`,
`mohawkcollege.ca`, `galiciaconfidencial.com`,
`installation-frigorifique-eure.fr`, `johnbellcroyden.co.uk`, and
`examcelltheemcoe.wordpress.com`. They include long compound, language-specific,
and hosted-subdomain first labels that can look unusual when isolated from their
full query. Other reference-labelled names are themselves random-looking; their
true status cannot be adjudicated from string shape. All 275 second-capture FPs
were observed as A queries, with none from reverse-DNS names.

Comparison FPs have median length **14** versus 9 for true negatives and mean
entropy **3.20** versus 2.68. Second-DNS FPs have median length **15** versus 9
and entropy **3.24** versus 2.74. Their mean digit ratios are *lower*, not higher,
than those of true negatives. The legacy hand-built English bigram surprise is
nearly identical in FP/TN groups (comparison 0.685/0.689, second DNS 0.652/0.666);
it cannot separate these errors. The learned TF-IDF n-grams are different from
that manual guard statistic.

## Feature-level diagnosis and current rule

The active conservative rule requires first-label length >=20, entropy >=3.5 and
manual bigram surprise >=0.8. On the comparison positives, **all 60,577 fail the
length requirement**; 47,771 also fail entropy. Entropy >=3.5 is mathematically
unreachable for a label of 11 or fewer characters (`log2(11) < 3.5`). This is the
reason the active rule detects zero positives on this particular comparison set.
The disabled candidate's result must not be conflated with this rule. The rule's
previous 7.97% recall came from a different, smaller cohort.

The candidate uses causal first-label character 2/3-grams and ten statistics in
both training and portable runtime scoring. No family ID, suffix, address, timing
or decrypted payload enters the model. Export verification and saved vectors show
no observed train/runtime feature mismatch. The representation is sufficient for
some long random-looking families (murofet_v1/v3 each 100% in validation) but **has
not demonstrated sufficient generalization** to short/pronounceable or the
hexadecimal-shaped ccleaner family. First-label-only scoring also discards real
query context, such as whether a label is a hosted subdomain. That is a structural
limit, not a reason to add unavailable runtime features or a public-suffix lookup
without a separate test.

The linear encoding has positive standardized coefficients for log length (+1.96)
and entropy (+0.80), but a negative coefficient for digit-run length (-1.88).
Missed ccleaner labels have mean digit-run statistic 0.471 versus 0.251 for detected
ccleaner labels, consistent with that learned bias. The boosted trees split on the
linear logit in 330/673 internal nodes and log length in 130/673, then consonant
runs (61), hyphens (49), vowels (47) and entropy (41); raw digit ratio is used in
only two nodes. These are **associations and model structure, not causal feature
importance**. The current trainer feeds the tree the logistic model's *in-sample*
training scores, whereas held-out/runtime scores are out-of-sample. That may
encourage an optimistic stacked decision boundary; its effect is unmeasured.

Training is near class-balanced (69,993 DGA; 67,715 benign), so global class
imbalance is not the primary explanation. **Family/shape distribution** remains a
plausible main factor: training has 11,107 long alphabetic benign labels versus
35,770 long alphabetic positives, and the per-variant 2,000-row cap gives
multi-variant families more group weight. Validation also includes 30,000 easy
murofet variant labels out of 80,000 positives, whereas the comparison contains
shorter and digit-run-heavy families. This explains why aggregate validation
recall can mask family-specific weakness; it does not by itself prove a fix.

## Partition and evaluation independence audit

The current candidate has **zero exact scored-label overlap** among training,
validation and domain comparison, and zero related-family-group overlap across
those splits. Twenty labels present in both positive and benign raw sources are
excluded; zero positive labels had to be removed for cross-split overlap. The
second DNS check excludes all training labels and all first-capture labels. Three
of its labels occur somewhere in the raw positive files, but none in any selected
positive train/validation/comparison row. Publisher/reference disagreement is
possible; these three are not silently reclassified.

The second DNS check is **not independent of both held-out domain sets**: 1,278
labels overlap validation and 1,260 overlap comparison. The remaining 9,193 are
disjoint from those splits and have 239 FPs (2.60%). The overlap strata have
19/1,278 and 17/1,260 FPs respectively. These post-hoc strata expose dependence;
**275/11,731 (2.34%) remains the frozen gate result**. The validation overlap is
particularly relevant because validation was used to select the threshold.

The older, disabled character-bigram NB trainer hashed full FQDNs into splits but
scored only first labels. Its reconstructed scored-label overlaps are 6
training/validation, 5 training/test and 2 validation/test, despite zero exact
FQDN overlap. That is a legacy partition defect, separate from the current
candidate; this diagnostic does not retrain or repair the old artifact.

There is no evidence of current **exact-vector train/validation/test leakage**.
There is still developmental exposure: the comparison-family results were
inspected during earlier iterations, and both domain sets and the DNS reference
come from previously used sources. None is an untouched final test. All datasets
and model artifacts remained byte-identical through this diagnostic run.

## Smallest next experiment — recommendation only

Freeze a *new* independent evaluation set and its acceptance criteria before
looking at its labels or outcomes. Then run **one training-only, length/shape-
stratified benign weighting experiment** with the existing candidate architecture,
runtime-compatible features and fixed validation threshold grid. Give the already
available long alphabetic benign examples enough weight to counter the training
shape prior; do not add new sources, features or thresholds in that experiment.
Compare per-family recall (especially ccleaner, symmi and kraken), long-alphabetic
FP counts, full comparison metrics and original second-DNS FPR against this
baseline. The old comparison and DNS sets are development diagnostics only; use
the independent set once for a genuine final assessment, not tuning. If the
training-only weighting does not improve the predeclared trade-off, keep the
candidate disabled and investigate the in-sample stacked-logit issue as a
separate, later hypothesis. **No such experiment was run here.**

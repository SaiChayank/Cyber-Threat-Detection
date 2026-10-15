# DGA lexical feature and rule validation — 30 September 2026

This is a **training/validation-only** comparison under the frozen
[DGA evaluation design](DGA_EVALUATION_PROTOCOL.md). The final reserved sources
have not been materialized, so no final evaluation or promotion occurred. The
public candidate artifact `ml/dga_v2.json` and its SHA256 remain unchanged and
disabled. `python -m datasets.compare_dga_rules --output docs/verification/dga-rule-comparison-new.json`
reproduces the counts in
[`ml/dga_rule_validation.json`](../ml/dga_rule_validation.json) without fitting,
exporting or replacing a model. Choose an unused output filename: existing reports
are now rejected before data loading rather than overwritten. It never scores the
already-inspected comparison families or second DNS capture. The historical
30 September measurements below are preserved; the fresh 2 October measurement
and task disposition follow them.

## Minimal hypothesis and causal implementation

The diagnostic showed that the active length-20/entropy-3.5/manual-bigram-0.8
rule rejects all comparison positives by length, while legitimate long
alphabetic labels account for most candidate false positives. The current
candidate already computes first-label vowel ratio and maximum consonant-run
ratio. Rather than invent a new predictor, this experiment makes those **same
existing lexical definitions** available to the streaming feature extractor and
tests one short/long rule hypothesis:

- Short labels (length 8–15): entropy >=2.5, manual bigram surprise >=0.9,
  vowel ratio <=0.2, maximum consonant-run ratio >=0.35.
- Longer labels (length >=16): entropy >=3.4, manual bigram surprise >=0.8,
  vowel ratio <=0.3.

All inputs come from the observed first DNS label, so the rule needs no future
queries, network resolution, source identity, payload or family label. The
feature extractor and offline comparison call the same lexical feature function.
Exact tests check case/suffix independence, entropy, digit ratio, bigram score,
vowel ratio, consonant run, and rule boundaries. The existing active rule is
still selected in `detection/pipeline.py`; the new rule is a **validation-only
configuration**.

## Comparison on existing development partitions

The current candidate uses its frozen 0.9 score threshold and existing
first-label character 2/3-gram TF-IDF plus ten lexical statistics. It is scored
offline despite being disabled; `predict()` still abstains at runtime.

| Configuration, validation | TP | FN | FP | TN | Recall | Precision | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Active old rule | 19,374 | 60,626 | 24 | 15,212 | 24.22% | 99.88% | 38.98% | 0.16% |
| New validation-only rule | 45,255 | 34,745 | 68 | 15,168 | 56.57% | 99.85% | 72.22% | 0.45% |
| Current disabled candidate features | 73,577 | 6,423 | 268 | 14,968 | 91.97% | 99.64% | 95.65% | 1.76% |

On the training partition, the old rule catches **5,447/69,993** positives
(7.78%) with 71/67,715 benign false positives (0.10%). The new rule catches
**16,872/69,993** (24.11%) with 227/67,715 benign false positives (0.34%).
On validation, the new rule catches **16,610 positives with labels under 16
characters**, where the old rule catches none. It also flags 38 short benign
labels, versus none for the old rule. Overall it flags 68 benign labels versus
24 for the old rule, so it **does not reduce false positives relative to the
active rule**. It does reduce validation false positives relative to the disabled
candidate, but gives up 35 percentage points of recall. Its proslikefan recall
is only 21.78%, compared with 62.95% for the candidate. A short pronounceable
DGA problem remains.

The current candidate features are the **best validation-time configuration**
under the fixed recall/precision/FPR gates; the experimental rule is the better
rule-only recall/FPR trade-off but fails the 80% recall gate. This selection is
*not* promotion: the candidate's earlier inspected comparison recall (76.77%)
and separate benign-DNS FPR (2.34%) failed the unchanged gates. Neither the new
rule nor the candidate is activated by this task.

## Runtime cost and scope

On 5,000 preselected validation labels, five repeats on this Windows/Python
3.13.5 host, the old four-field lexical calculation took a median **4.32 µs
per label** and the shared six-field calculation **8.69 µs per label**. This is
an extra **4.37 µs per label** for two available vowel/consonant fields plus
the shared candidate-feature computation. The check verified that the old four
values remain exactly equal. A separate 20,000-event core + SQLite smoke
measurement processed **3,299 metadata events/sec** at **0.99 ms p95** on the
existing synthetic workload. That measurement excludes capture parsing,
API/SSE delivery and browser rendering; it is not an activated-candidate
throughput claim. Host load and microbenchmark variance prevent a precise
before/after whole-pipeline speedup claim.

The feature/rule choice is limited by source-labelled domain strings,
family distribution and a validation set rich in easy long murofet names.
No independent contemporary reserved set is available. The next separate task
would need to materialize that set before any final gate claim; another candidate
experiment may use training/validation only. No threshold or gate was relaxed.

## Feature/rule reconfirmation — 2 October 2026

Inspected the frozen evaluation protocol and exposure supplement, diagnostic
findings, active/experimental rules, shared runtime extractor, portable candidate
features, training loader, comparison script, unit tests and saved reports. No
reserved materialization exists. The loader checks previously exposed development
sources, but only training/validation rows are scored here. Comparison-family and
second-DNS outcomes were not recomputed; no final data was opened or scored.

### Frozen feature choice and scope

Retain the existing **first-label character 2/3-grams plus ten lexical features**
for the next separately authorized candidate experiment. Its frozen 0.9 threshold
is unchanged. The rule-only alternative remains the already specified two-branch
`validation_rule`; the active `conservative_rule` is unchanged. This task adds
no new predictor, threshold, fitted candidate or runtime activation.

Vowel/consonant ratios, digit/hyphen ratios, normalized character runs, repeat
ratio and unique ratio already exist in the exact training/runtime function
`ml.dga.lexical_features`. The rule and streaming extractor reuse those definitions.
Adding duplicates would not address the measured error. Entropy and manual
bigram surprise are not sufficient maliciousness evidence: short labels have a
low maximum attainable entropy, and legitimate non-English/compound names can
have unusual bigrams. The first-label length floor also prevents the old rule
from catching short labels. Total FQDN length remains a shared legacy field,
not a new DGA candidate input.

Label count/max-label length would require retaining full-name context in the
frozen first-label training rows. Reconstructing a suffix for those rows would
fabricate information; mixing the current first-label features with such
reconstructed context is unjustified. No reputation, lookup, payload, timing,
family label, address or future-query feature is introduced. The causal feature
contract and other detectors remain unchanged.

### Fresh comparison and failure limitations

Evidence: [fresh comparison JSON](verification/dga-feature-rule-review-20261002.json).
The report pins the protocol, exposure supplement, candidate and comparison
script hashes. Training and validation selected-row digests are verified against
the frozen manifest before scoring. The JSON retains per-family confusion counts.

| Validation configuration | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Active old rule | 19,374 | 15,212 | 24 | 60,626 | 99.88% | 24.22% | 38.98% | 0.16% |
| Validation-only rule | 45,255 | 15,168 | 68 | 34,745 | 99.85% | 56.57% | 72.22% | 0.45% |
| Current disabled candidate features | 73,577 | 14,968 | 268 | 6,423 | 99.64% | 91.97% | 95.65% | 1.76% |

These validation counts match the historical report exactly: **no accuracy gain
is claimed for this reconfirmation**. The alternative adds 25,881 TPs and 44 FPs
versus the active rule. It flags 38 short and 30 longer benign labels versus
the active rule's 24 longer benign labels, while catching 16,610 short positives.
It fails the unchanged 80% recall requirement and remains inactive.

| Training configuration | TP | TN | FP | FN | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Active old rule | 5,447 | 67,644 | 71 | 64,546 | 7.78% | 0.10% |
| Validation-only rule | 16,872 | 67,488 | 227 | 53,121 | 24.11% | 0.34% |
| Current disabled candidate features | 55,378 | 67,000 | 715 | 14,615 | 79.12% | 1.06% |

Candidate training scores are in-sample diagnostics, not generalization evidence.
The validation cohort has easier family composition; its higher recall does not
invalidate the training count or prove broader coverage. Pronounceable-family
coverage remains inadequate: validation `proslikefan` recall is 21.78% for the
alternative versus 62.95% for the candidate. The former produces 7,822 of its
34,745 validation misses in that family; other missed families include
cryptolocker, fobber variants and locky. The current candidate remains the best
of these configurations on the three development domain gates, but all four
final promotion gates are unchanged and **not passed** by this work. Its saved
comparison recall 76.77% and second-DNS FPR 2.34% remain failed historical evidence,
not newly measured results. Both public candidate artifacts stay disabled.

The simultaneous goals of fewer active-rule false alarms and broad
short/pronounceable coverage are **not achieved by the tested rule**. No threshold
search, family-specific exception, additional rule sweep or new training is used
to make that result appear to pass.

### Fresh runtime measurement

Python 3.13.5, `AMD64 Family 25 Model 117 Stepping 2, AuthenticAMD`; 5,000
preselected validation labels, five repeats after warm-up. Values are medians
of mean per-label duration across repeats, **not latency percentiles**.

| Operation | Microseconds/label |
| --- | ---: |
| Historical four-feature computation | 4.63 |
| Shared six-field rule representation | 8.70 |
| Active rule plus shared features | 8.73 |
| Alternative rule plus shared features | 8.91 |
| Disabled candidate uncached inference | 56.07 |

The alternative decision adds approximately 0.18 microseconds over the active
decision with the same shared extraction in this run. Comparing four-field and
six-field extraction measures the previously implemented representation's cost,
not a new runtime change in this task. Candidate timing excludes name
canonicalization, cache lookup and activation; it uses `_uncached_score` only
offline. No packet parsing, state windows, persistence, API, SSE or browser work
is included, so this is neither end-to-end throughput nor a new core benchmark.

### Implementation changes, tests and disposition

Only the DGA diagnostic comparison script changes: explicit `--output`, refusal
to overwrite existing evidence, frozen development-row verification, added
training candidate scores, source hashes/date and rule/scorer timing. The old
hash-pinned rule report and exposure manifests remain untouched. A regression
test verifies the overwritten-report defect is fixed before any data/model load;
another verifies changed frozen partitions are rejected before scoring.

Exact regressions cover all ten character statistics, normalized bigram behavior,
short/long rule boundaries and DNS lexical independence from peer history/future
events. No detector code, shared extractor, model artifact or other threat feature
changed. Targeted DGA tests: **57 passed**. Full backend suite: **240 passed** in
47.07 seconds, with one existing FastAPI/Starlette HTTPX deprecation warning.
No unrelated detector regression was observed. The frontend build was not rerun:
no frontend code, shared runtime behavior or alert/API contract changed.

**Definition of Done:** the validation-time feature/rule configuration is stable
and its comparison/runtime cost are reproduced. Quality improvement remains
unresolved; neither rule nor candidate is promoted. Freeze these existing feature
definitions, thresholds, tests, disabled artifact versions, numerical report and
limitations. The smallest next experiment is the diagnostic's already recommended
training-only three-fold family-grouped out-of-fold logit stacking, keeping the
same features/hyperparameters/unweighted baseline/0.9 threshold. It is **not
implemented here**. Independent reserved materialization remains required for
any later final evaluation; no future task starts automatically.

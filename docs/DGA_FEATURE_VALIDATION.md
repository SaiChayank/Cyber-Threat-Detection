# DGA lexical feature and rule validation — 30 September 2026

This is a **training/validation-only** comparison under the frozen
[DGA evaluation design](DGA_EVALUATION_PROTOCOL.md). The final reserved sources
have not been materialized, so no final evaluation or promotion occurred. The
public candidate artifact `ml/dga_v2.json` and its SHA256 remain unchanged and
disabled. `python -m datasets.compare_dga_rules` reproduces the counts in
[`ml/dga_rule_validation.json`](../ml/dga_rule_validation.json) without fitting,
exporting or replacing a model. It never scores the already-inspected comparison
families or second DNS capture.

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

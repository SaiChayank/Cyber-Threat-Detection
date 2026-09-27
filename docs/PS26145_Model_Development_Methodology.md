# PS26145 — Model-Development Methodology
**Scope:** How models get trained, validated, tuned, calibrated, tracked, and versioned. No runtime/serving system design here — that is deferred to a later task. Applies across the seven per-detector models chosen in the prior task, within the rules+classifiers hybrid architecture.

---

## 1. Train / Validation / Test Strategy

**Splitting unit is the experiment, not the flow.** Every artifact in the lab's storage structure traces back to one `experiment_id` (established in the lab-architecture task). Splits are assigned **at the experiment level**: all flows/DNS records/sessions belonging to one experiment run land entirely in one split. Splitting at the flow level instead would let strongly correlated flows from the same attack run (e.g., a single hping3 flood's constituent packets) appear on both sides of a split — an easy, very common source of inflated validation performance that this design avoids by construction.

**Nominal ratio:** roughly 60% of experiments for training, 20% for validation (model selection, hyperparameter tuning, threshold tuning, calibration fitting), 20% for test (final, single-use evaluation). Exact ratios are adjusted per detector to ensure every split contains at least a minimal number of positive-class experiments, given that some threats (e.g., C2 beaconing, encrypted-session malware) may have fewer total lab runs than others — stratification (below) governs this more than a fixed ratio.

**Stratification:** experiment assignment to splits is stratified by `threat_class` (so every split contains benign and all seven attack types, not just whichever happened to fall into it by chance) and, where feasible, by `tool_used`/configuration (so, e.g., both dnscat2- and iodine-based tunnelling experiments appear in more than one split rather than one tool being entirely absent from validation or test).

**Supplementary public datasets** (CIC-DDoS2019 attack-side, CTU-13, CIRA-CIC-DoHBrw-2020, per the earlier dataset-evaluation decision) are **not blended into this train/validation/test split at all**. They are held out entirely as a **separate, independent validation set**, used only to sanity-check generalization beyond the lab's own generators — consistent with the earlier decision to treat them as supplementary validation, not primary training material.

---

## 2. Temporal Splitting

Within the training/validation/test assignment above, a **secondary temporal ordering constraint** applies: experiments are also ordered chronologically by their `date`/`experiment_id` timestamp, and — where the stratification requirement above can still be satisfied — later-dated experiments are preferentially assigned to validation/test rather than training. This produces a **walk-forward-style evaluation**: the model is validated and tested on lab runs conducted *after* most of its training data, which is the more honest analogue of "will this generalize to traffic generated tomorrow" than a purely random split would be.

This is a soft preference, not an absolute rule, because strict chronological cut-off could, for some sparser threat classes, leave too few early-dated positive examples to train on at all — stratified class balance takes priority where the two constraints conflict, and any such conflict/exception is logged explicitly (see experiment tracking, §8) rather than silently resolved.

---

## 3. Scenario Separation

Beyond time, splits are also checked for **configuration diversity**, addressing a different generalization question than the temporal split does: *does the model generalize to attack variants it wasn't trained on*, independent of when they were run.

- At least one distinct tool-parameter configuration per threat (e.g., a specific hping3 flood rate, a specific C2 emulator jitter setting, a specific DGA family from DGArchive, a specific dnscat2 vs. iodine tool choice) is **deliberately withheld from training** and reserved for test — a **configuration holdout**, separate from and in addition to the temporal holdout in §2.
- This produces two meaningfully different test conditions worth reporting separately: performance on **held-out time** (same configurations, later runs) versus performance on **held-out configuration** (unseen attack parameterization, regardless of when it was run). A model that does well on the former but poorly on the latter is memorizing specific attack signatures rather than learning the general behavioral pattern the feature-engineering task intended to capture — an important distinction to surface honestly rather than blur into one aggregate number.
- Benign traffic diversity is checked the same way — not every split should be dominated by identical repeated benign-generator runs at the same settings, or the model may learn a narrow definition of "normal."

---

## 4. Leakage Prevention

Consolidating and extending the causality/leakage discipline already established in the feature-engineering task, specifically for the model-development stage:

- **No experiment appears in more than one split** (§1) — the primary defense against flow-level correlation leakage.
- **No overlapping time windows for the same source/destination pair across splits** — even across *different* experiments, if two experiments happen to reuse the same lab IP addresses in overlapping time windows (a lab-hygiene edge case), the affected windows are excluded or resolved to a single split rather than left ambiguous.
- **Static reference artifacts** (the DGA n-gram language model, any known/suspicious JA3 fingerprint list) are built **exclusively from the training split**, never from validation or test data, and never refreshed using validation/test-period information — repeating the discipline flagged in the feature-engineering task, now applied concretely to which specific rows are allowed to build these tables.
- **Deduplication happens before splitting**, not after — using the same composite-key/`flow_id` deduplication already established, so an accidentally duplicated record can't land in two different splits and silently create train/test overlap.
- **Class-imbalance resampling (§5) is applied only to the training split**, never to validation or test — oversampling or undersampling the evaluation data would distort the very metrics meant to measure real-world performance.
- **Threshold tuning and calibration fitting (§7, §8 in the earlier numbering — here §7/§8 below) use the validation split only**, with the test split touched exactly once, at the end, for final reporting — never used to iterate.
- **Supplementary public datasets are never merged into the training rows** (§1) — the specific leakage risk here is subtler: even using their *statistics* (e.g., their benign traffic's typical volume) to inform lab threshold choices would be a soft form of leakage between "final validation set" and "model development," so they are treated as strictly post-hoc validation only.

---

## 5. Class Imbalance Handling

- **Primary mechanism: class weighting** in the training objective (per model, as specified in the model-selection task) — inflating the loss contribution of minority-class (attack) examples relative to the dominant benign class, tuned per detector since the degree of imbalance genuinely differs (e.g., DDoS attack windows are dense once triggered; C2 beacon events are comparatively sparse across a long observation horizon).
- **Secondary mechanism, where class weighting alone proves insufficient during validation:** oversampling of minority-class training examples (synthetic or duplication-based) or undersampling of the benign majority — applied **only within the training split** (§4).
- **Stratified split assignment (§1)** ensures every split retains at least some minority-class representation, rather than a rare class disappearing entirely from validation or test by chance.
- **Metric choice itself is part of imbalance handling** — macro-averaged and PR-AUC-based metrics (§9–§10) are chosen specifically because they don't let a large benign class mask poor minority-class performance the way accuracy or micro-averaged metrics would (elaborated in §12).

---

## 6. Hyperparameter Tuning

- Conducted **on the training split only**, using either a held-out portion of training data or **grouped k-fold cross-validation** — "grouped" meaning folds are assigned by `experiment_id` (same rule as §1), so cross-validation folds don't reintroduce the same flow-level leakage the primary split was designed to avoid.
- Given hackathon time constraints, a **constrained search** (random search over a modest parameter grid, or a small number of manually-chosen configurations informed by the model-selection task's known-good defaults for each family) is preferred over exhaustive grid search — thoroughness is traded for time, deliberately and explicitly, rather than left unstated.
- Representative search dimensions per model family (illustrative, not exhaustive): tree count/depth and class-weight ratio for Random Forest/Extra Trees; learning rate, tree depth, and `scale_pos_weight` for XGBoost/LightGBM; regularization strength for Logistic Regression; sequence length, hidden-unit count, and dropout rate for the optional-advanced temporal models (GRU, Temporal CNN, character-level CNN).
- **The test split is never touched during hyperparameter search** — this is the same discipline as §4, restated here because it's the single most common way this kind of methodology quietly breaks down in practice.

---

## 7. Threshold Tuning

- Every classifier outputs a continuous score; the decision threshold that turns that into an alert is tuned **on the validation split**, per detector, per class (for the binary-per-threat models) — never on test.
- Tuning target differs by detector, reflecting the earlier rule-baseline findings and the PS's own operational framing: **high-volume, fast-onset threats (DDoS, reconnaissance)** are tuned to prioritize a **low false-positive rate**, since a SOC analyst facing constant false alarms from the busiest detectors will rationally start ignoring them; **stealthier, harder-to-observe threats (C2 beaconing, encrypted-session malware)** are tuned to prioritize **higher recall**, accepting a somewhat higher false-positive rate, since missing these has a proportionally worse consequence than an extra alert to triage.
- The threshold and the reasoning behind where it was set are recorded per model version (§8) — not just the final number, so a future reviewer (or judge) can see *why* a given operating point was chosen, not just what it is.

---

## 8. Confidence Calibration

- Raw scores from tree-ensemble models (Random Forest, XGBoost/LightGBM) are known to not directly correspond to true probabilities — a raw score of 0.9 doesn't necessarily mean "90% of examples scored this way are truly positive." Since the official alert schema requires a **confidence score**, this gap needs to be closed rather than reporting a raw, uncalibrated score as if it were one.
- **Calibration method:** Platt scaling (logistic calibration) or isotonic regression, fit **on the validation split only**, mapping each model's raw score to a calibrated probability. Isotonic regression is preferred where enough validation data exists (it makes fewer distributional assumptions); Platt scaling is the fallback for detectors with fewer validation-split positive examples, where isotonic regression's more flexible fit would risk overfitting to a small sample.
- **Evaluation of calibration quality** (not the calibration fitting itself) happens on the test split, using the calibration metrics defined in §10 — this is the one place test data legitimately gets used for something calibration-related, since *evaluating* whether calibration worked is different from *fitting* it.
- This calibration step is explicitly what will feed the alert schema's `confidence_score` field in the eventual runtime system (a later task) — this document only establishes the calibration methodology, not the runtime integration.

---

## 9. Experiment Tracking

Every training run (regardless of which detector or model family) is logged with, at minimum:

- A unique **run ID**
- The exact **training-data snapshot** used (which experiment IDs, from the lab's storage/index structure, were included in train/validation/test for this run — since the experiment pool itself may grow over time as more lab runs are conducted)
- **Feature-engineering code version** used to compute the input features (since the feature definitions themselves could evolve — an important detail, since a metric improvement could otherwise be wrongly attributed to a better model when it was really a feature-computation fix)
- **Hyperparameters** used and the search process that selected them (§6)
- **Random seed(s)** for reproducibility
- **Resulting metrics** per split (§10–§11), including per-class breakdowns, not just the aggregate
- **Chosen decision threshold and calibration parameters** (§7–§8)
- Any **exceptions logged** to the temporal/scenario-separation rules in §2–§3, per the honesty note there

This mirrors, deliberately, the same discipline the lab-architecture task established for experiment metadata manifests — the same instinct (full auditability, nothing asserted without a traceable record) applied to the ML side of the pipeline rather than the data-generation side. No specific tracking tool is mandated here (a structured log file, spreadsheet, or a dedicated experiment-tracking tool are all compatible with this methodology) — the requirement is the content of what's tracked, not the tool.

---

## 10. Model Versioning

- Each trained model artifact receives a **version identifier** linking it to: the experiment-tracking run ID that produced it (§9), the feature-schema version it expects as input, the calibration parameters bundled with it, and the decision threshold it was shipped with.
- **A model version is immutable once evaluated on the test split** — if the model is retrained (new data, new hyperparameters, or a feature-schema change), it becomes a new version rather than overwriting the old one, preserving the ability to compare "did the new version actually improve things" against a known-good prior baseline.
- Any alert the eventual runtime system produces should be traceable back to the specific model version that generated it (an auditability requirement that anticipates, but does not design, the runtime system itself) — this is a design intention carried forward for the later runtime-design task, not something implemented here.
- Superseded versions are retained (not deleted) to support rollback if a newly trained version regresses on a metric that matters operationally (e.g., false-positive rate on the DDoS detector spiking after a retrain).

---

## 11. Why Accuracy Alone Is Insufficient

Accuracy is explicitly **not** used as a primary metric, for reasons directly tied to this system's known characteristics:

1. **Severe class imbalance makes accuracy trivially gameable.** With benign traffic vastly outnumbering any single attack class (an established constraint from the requirements task), a classifier that predicts "benign" for everything can score extremely high accuracy while catching zero attacks — the exact failure mode this system exists to prevent, and one accuracy cannot distinguish from a genuinely good detector.
2. **Accuracy weights all errors equally**, but in this domain a false negative (a missed attack) and a false positive (a false alarm) have very different real-world costs — a missed DDoS or exfiltration event is categorically worse than an extra alert an analyst has to dismiss. Accuracy has no way to reflect that asymmetry.
3. **Accuracy is a single aggregate number that can hide which class is actually failing.** In a seven-class-plus-benign setting, a model could post a superficially strong overall accuracy while having near-zero recall on the one class that matters most for a given failure scenario (say, C2 beaconing) if the other six classes and the dominant benign class compensate in the average.
4. Because of (1)–(3), any metric or claim expressed only as "accuracy" would be actively misleading for this specific system, and is deliberately excluded from the primary reporting metrics below.

---

## 12. Metrics

**Primary aggregate metric: Macro F1.** The unweighted mean of per-class F1 scores — every class (benign plus all seven threats) contributes equally to the aggregate regardless of how many examples it has, directly countering the imbalance-masking problem in §11.

**Per-class precision, recall, and F1** — reported for every class individually, not just the macro average, since (per §11) an aggregate number alone can still hide a single class's failure. This is the primary diagnostic view during development, not just a final-report table.

**False Positive Rate (FPR)** — reported per class and overall, given the PS's own operational framing (SOC analysts need to trust the alert stream) and the earlier rule-baseline task's finding that different threats warrant different FPR tolerance (§7's threshold-tuning targets are directly informed by this metric).

**PR-AUC (Precision-Recall Area Under Curve)** — preferred over ROC-AUC as the primary threshold-independent ranking metric for each detector, specifically because PR-AUC is far less optimistic than ROC-AUC under severe class imbalance (ROC-AUC can look deceptively strong when negatives vastly outnumber positives, since the false-positive rate axis it's built on is diluted by the huge negative class).

**ROC-AUC** — still reported as a secondary, complementary metric, mainly because it's a more universally recognized number for comparison against other published work (e.g., the public datasets' own reported benchmarks) — reported alongside, never in place of, PR-AUC.

**Calibration metrics** — Brier score and Expected Calibration Error (ECE), plus a reliability diagram for qualitative inspection, evaluated on the test split per §8, to verify that the calibration step (Platt/isotonic) actually produced trustworthy confidence values rather than just visually plausible ones.

---

## 13. Team Targets

**These are internal team targets for tracking progress during development — they are not official SIH requirements**, and are explicitly distinguished from the earlier requirements-analysis task's finding that PS-DOC's own numeric targets (Macro F1 > 0.85, FPR < 5%, latency in "tens of ms") were themselves an **ASSUMPTION**, not SIH-mandated. The team targets below are deliberately set independently, and somewhat more conservatively for the earlier stages, precisely because lab-generated data provides no guarantee that a number achieved in the lab transfers to real-world traffic.

| Metric | MVP-stage team target | Stretch-goal team target |
|---|---|---|
| Macro F1 (across all 8 classes including benign) | ≥ 0.70 | ≥ 0.85 |
| Per-class recall (each of the 7 threats individually) | ≥ 0.65 minimum for every class — no class left at near-zero recall | ≥ 0.80 |
| False Positive Rate — high-volume detectors (DDoS, reconnaissance) | ≤ 10% | ≤ 5% |
| False Positive Rate — other detectors | ≤ 15% (looser, reflecting the harder detection problem and acceptance of the recall-over-precision tuning bias in §7) | ≤ 10% |
| PR-AUC (classifier-primary detectors: C2, DGA, DNS tunnelling, encrypted malware, exfiltration) | ≥ 0.70 | ≥ 0.85 |
| Expected Calibration Error (ECE) | ≤ 0.15 | ≤ 0.08 |

These targets are intentionally set as **internal milestones to organize development effort and honestly track progress**, not as claims to present as SIH-mandated pass/fail bars in a submission — consistent with the earlier requirements-analysis task's caution against quoting PS-DOC's own aspirational numbers as if NTRO required them.

---

**No runtime/serving system has been designed in this document** — deployment architecture, streaming integration of the trained models, and how alerts are actually produced in production are deferred to a later, explicit task.

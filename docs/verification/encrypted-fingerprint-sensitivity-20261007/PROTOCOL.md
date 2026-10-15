# Frozen offline sensitivity protocol — 7 October 2026

Record before running this experiment. This is **not** model training, a new
candidate, reserved evaluation, runtime integration or promotion.

- Use exactly the 18 already evaluated cases in `datasets/validate_encrypted.py`,
  in their original order, with each existing 20-event stream and saved SHA256.
  Verify generator provenance and the existing raw model hash before prediction.
- Verify all current source pins in the frozen offline feature contract. Its
  current conformance is not proof of historical model compatibility or quality.
- Obtain causal features from the actual default Pipeline. Observe its original
  GNB prediction, make a separate feature-dictionary copy with only
  `fingerprint_risk=0`, and predict using the same frozen GNB. Return **only the
  original prediction** to Pipeline. Never erase an observed fingerprint/event.
- Keep the original 20 features/order/transform, model parameters, top-posterior
  cutoff **0.8**, rules, guards, replay timestamps and labels unchanged. No labels,
  filenames, addresses or scenario IDs are added as predictive features.
- Preserve original features and explicit counterfactual value, each top label /
  top posterior, target hit, event index/time, and first target-model-hit timing.
  Model supplies top-class posterior, not all per-class probabilities/calibration.
- Summarize lab positives, shared-fingerprint benign controls, other benign and
  novel/no-lab-fingerprint positives. Record gains/losses; never hide a worse result.
- Model-only scenario counts use existing semantics: positive target hit before
  last event = TP; otherwise FN. Any target hit in a benign scenario = FP.
  These are sensitivity results on seen controlled data, not production accuracy.
- Replay the original pipeline and check first alert, evidence, verdict and
  original model/rule hit counts against the saved encrypted report. Counterfactual
  predictions do not emit alerts; do not label their metrics full-hybrid metrics.
- Four existing lab-fingerprint scenarios contain 80 positive risk bits; the other
  280 events are negative controls. Only that bit can differ in model input; zero
  risk must yield identical paired predictions. Observed rule matches remain intact.
- Add targeted regression tests. Verify artifacts, runtime source, historical
  reports, prior diagnostics/tests, raw data and analyst history remain unchanged.
  Shared runtime/frontend changes are forbidden, so no new full build is required.

Definition of Done is a reproducible, tested sensitivity report with unchanged
runtime and explicit limitations. Existing encrypted quality criteria remain
recall>=80%, precision>=95%, FPR<=2% and early detection. They are **not** promotion
gates for this diagnostic; no candidate may be activated from its results.
Stop after recording the result and recommending one smallest next action.

# T25 possible-exfiltration observability diagnosis protocol

18 October 2026 IST; baseline `1f99d49`. Freeze before diagnostic edits/replays.
Only eleven previously exposed `validate_exfil.CASES`, saved report/evidence and
the already tested explicit-zero reverse fixture may be used. Preserve original
generator, model, rules, feature definitions, artifacts and historical counts.

Add `--group EXFIL` to the existing diagnostic, preserving its default output
semantics and all other scoped diagnostics. Replay only four recorded false-positive
prefixes, requiring exact first position, source and evidence. Positive/FN quality
results remain historical. Trace causal forward bytes/rate, ratio availability/
status and volume-rule eligibility through FeatureExtractor without prediction.
Compare every prefix against the existing independent source/time reference.

Audit four complete opposite-label transfer pairs in raw metadata, full runtime
features and model vectors. Distinguish unknown reverse traffic, explicitly
observed zero (finite ratio undefined), and finite observed per-event ratio.
Do not fabricate reverse zero, aggregate unobserved directions or claim Internet
egress/stolen content from forward bytes. Preserve one-second bucket resolution
and frozen bounded model-feature versus rule-evidence semantics.

Gate remains recall >=80% (4/5), precision >=95%, FPR <=2% (zero/six benign),
before-completion multi-event positives and the documented single-event exception.
No threshold >= substitution, longer horizon, source/destination/port shortcut,
ablation, model training, new data, reserved access, decryption or active lookup.
No rerun/overwrite of original validation reports or high-flow stress artifacts.

Add exact tests for causal boundaries, reference/label mismatches, scoped FP-only
prediction, four paired collisions and missing-versus-zero reverse semantics.
Any discrepancy must fail diagnosis rather than relabel saved outcomes. Inspect
runtime/feature/model code; change only diagnostic code and tests in this package.

DoD: exact FP attribution, causal window/ratio/pair diagnosis, one smallest next
experiment OR explicit observation/data blocker, targeted regressions and frozen
protected-file evidence. Stop this package before any detector experiment. Under
continuous-work authorization only then consider other independently eligible work.

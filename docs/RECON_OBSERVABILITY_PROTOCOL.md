# T24 reconnaissance observability diagnosis protocol

17 October 2026 UTC / 18 October IST; baseline `2ac33dd`. Frozen after reading
existing reconnaissance development code/report, before diagnostic edits/replays.
Only the eleven previously exposed `validate_recon.CASES` are allowed. Preserve
their generator, saved reports, historical counts and the deployed model bytes.

Reproduce only the three recorded false-positive prefixes through the unchanged
Pipeline, requiring exact first event, source and evidence. Positive/FN verdicts
remain historical; do not run a new quality matrix or tune a candidate. Audit
source-level causal fan-out/SYN evidence with FeatureExtractor and the existing
independent reference, without model prediction. Record guard/rule eligibility,
window maxima/final snapshots and early-prefix behavior. Eligibility is not an
actual model decision or ablation.

Verify complete opposite-label vertical and horizontal metadata/runtime/model
feature sequences, plus the service-discovery/shared-horizontal prefix. Distinguish
full-stream impossibility from prefix ambiguity; do not use eventual session
completion as evidence available to an earlier alert. Compare window-boundary
behavior without changing ten-second retention, model >=10 guard or rule >=20.
Do not infer malicious authorization from source names, addresses or scenario IDs.

Freeze the existing gate: recall >=80% (4/5), precision >=95%, benign FPR <=2%
(zero of six controls), required rapid/slower-vertical positives before completion.
No source data download, reserved set creation/access, model training, new features,
threshold adjustment, detector change, graph analytics or active probing. Any
dedup/model/extractor discrepancy is a diagnostic error, not a silently new verdict.

Minimal changes may extend only the existing failure-analysis diagnostic with
`--group RECON`, recon-specific histories/pair evidence and exact regression tests.
Default all-group behavior and other scoped outputs stay unchanged. No existing
runtime or model artifact is modified. Tests must reject changed saved labels,
snapshots and inappropriate inputs, enforce no prediction/training in causal-only
traces, and constrain scoped replay to only exposed recon FP prefixes.

DoD: source-matching FP attribution and causal window/pair diagnosis, one smallest
next experiment OR explicit visibility/data blocker, targeted regressions and
protected-file integrity. Stop this package after diagnosis; passing diagnostic
tests do not pass the failed threat-quality gate. Under continuous authorization,
only then advance to a separately scoped independent task.

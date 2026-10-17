# T25 possible-exfiltration observability diagnosis

18 October 2026 IST; baseline `1f99d49`. **Diagnostic DoD passes; intent-quality
gate remains unresolved.** No runtime/model/feature/threshold/artifact change,
reserved inspection, tuning, training, payload decryption or active lookup.

## Inspected and first false-positive attribution

Reviewed the eleven exposed transfer scenarios, frozen validation design/reports,
Pipeline combination/evidence, source byte buckets, bounded model features and
reverse-availability schema/tests. [Protocol](EXFIL_OBSERVABILITY_PROTOCOL.md)
was pinned before edits. The existing failure analyzer now supports `--group
EXFIL`; default and prior scoped behavior remain unchanged. A scoped option also
requires the first supporting-evidence text to match the saved record exactly.

All four known first false positives reproduce through the unchanged Pipeline:

- Cloud backup: **RULE**, event **6**, **25s**, 24 MB forward-window bytes.
- Large legitimate upload: **RULE**, event **1**, **0s**, 25 MB one-way volume.
- Synchronization: **ML**, event **1**, **0s**, 4 MB and explicitly observed
  per-event ratio 40. This precedes the volume rule; no isolated model ablation is
  performed or claimed.
- Replication/deployment: **RULE**, event **5**, **16s**, 25 MB forward-window bytes.

The diagnostic predicts only these four saved FP prefixes, **13 events total**.
Every saved first position, source, raw metric and supporting text matches.
Positive/FN confusion results remain historical; no new quality matrix is scored.

## Four complete opposite-purpose collisions

Each positive and its corresponding control are identical in entire metadata,
full runtime features, model vectors and existing volume-rule eligibility:

- One large one-way event / legitimate large upload.
- Sustained one-way transfer / cloud backup.
- Explicitly bidirectional transfer / synchronization.
- Volume-only one-way transfer / replication/deployment.

Content sensitivity and authorized business purpose do not occur in these inputs.
Changing entropy, rate/volume thresholds or the classifier cannot deterministically
separate each identical pair. Preserve every control rather than rename/remove
it to pass a gate.

For this small frozen five-positive/six-benign matrix only: zero benign FPs forces
missing all four paired positives, limiting recall to at most **1/5 =20%**. At
recall >=4/5, at least three paired benign controls must alert, so FPR >=**3/6=50%**
and best precision <=**4/7=57.14%**. These bounds concern deterministic decisions
on this exact observed matrix, not production FPR or a universal impossibility
claim about all context-enriched passive observations.

## Causal volume and reverse visibility

FeatureExtractor traces match the independent reference at every prefix for
the existing whole-second scenario times. That exact reference comparison is
scoped to those times, not fractional-second edges of the documented bucketed
windows. The diagnostic rejects off-scope times instead of silently treating
one-second buckets as exact subsecond event windows.

The rule remains **strictly >20,000,000** forward bytes. Five sustained 4 MB events
give 20 MB and no eligibility; event six gives 24 MB at 25s. The 15s-spaced slow
case reaches at most 20 MB inside the inclusive 60-second window and never meets
the rule. No horizon/threshold adjustment is made. Rule eligibility is not a new
emitted-rule confusion matrix; ML and deduplication still act in the real pipeline.

Missing reverse keeps availability 0, observed ratio null and status
`reverse_unavailable`. The existing explicitly observed-zero fixture retains
availability 1, ratio null and `zero_observed_reverse_bytes`; zero is not replaced
with one, infinity or a fabricated measurement. Finite observed bidirectional
ratios remain **per current event** (40 in the paired case), not lifetime forward
bytes divided by an unrelated reverse count. Source-forward bytes do not prove
Internet egress without sensor-placement context.

The frozen model's `egress_bytes` still uses its historical bounded event-history
feature, while the accurate volume rule/evidence uses the separate source byte
window. This existing distinction and 1,000ms bucket resolution are preserved;
the old high-flow fix is not retrained, rewritten or credited with new metrics.
Alerts retain “behavior consistent with possible exfiltration; content and intent
unverified” and the saved reverse-unavailable/volume-only qualifiers.

## Tests, quality and freeze

Added **24 exact tests** for windows, strict threshold/prefix boundaries, all four
full collisions, missing/observed-zero/finite ratios, invalid scope inputs, scoped
FP-only prediction, and saved label/reference/wording refusal. New tests pass
24/24. Combined exfil/recon/baseline/UDP/C2/spoof diagnostics and detector
regressions pass **121 tests in 5.88s**. No shared runtime code changed; these are
targeted results, not a newly labelled full backend/build pass.

Historical quality remains **TP4/TN2/FP4/FN1**, precision 50%, recall 80%, FPR
66.67%; recall >=80%, precision >=95%, FPR <=2% and early/single-event exception
gates are unchanged. No new candidate is promoted. The deployed legacy baseline
stays unchanged with disclosed intent limitations. Model SHA256 remains
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
Source pins, reports, tests and protected-file checks are in
`verification/exfil-observability-20261018/`.

## Smallest next action and stop

Qualify one independently labelled authorized/unauthorized transfer pair with
matching service/load, original timestamps and justified passive destination or
host-baseline context that actually differs independently of the labels. Do not
substitute addresses, filenames or business-purpose labels as predictors. If
context is unavailable, an explicit claim/scope decision is required; no further
threshold/model experiment on these identical inputs is justified.

T25 diagnosis is frozen; required intent quality remains blocked. Under continuous
authorization, next run the full backend regression suite after the two diagnostic
extensions, then check frontend TypeScript/build on the current baseline. This is
current-baseline non-regression evidence, not final release T50/T60 closure.

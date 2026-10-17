# T24 reconnaissance observability diagnosis

18 October 2026 IST; baseline `2ac33dd`. **Diagnostic DoD passes; malicious-intent
quality gate remains unresolved.** No rule, model, runtime feature, artifact,
deduplication behavior, threshold or reserved data changed.

## Inspected and reproduced

Reviewed current Pipeline fan-out rule/model guard, causal extractor, existing
independent recon reference, eleven previously exposed generators, saved reports
and tests. [Protocol](RECON_OBSERVABILITY_PROTOCOL.md) was frozen before diagnostic
edits. The existing failure analyzer now accepts `--group RECON`; its default
five-group behavior and the UDP/C2/SPOOF scopes are retained.

All **three recorded first false positives reproduce exactly** through the actual
unchanged Pipeline: authorized vulnerability scanning, authorized asset inventory
and service discovery. Each first alert is **ML**, event **10**, **0.9 seconds**
after the first observation, with the saved host/port/SYN evidence unchanged.
Only those three known false-positive prefixes (30 predictions total) are replayed
for this attribution report. Positive/FN verdicts remain historical, not a newly
scored quality matrix. Model SHA256 remains
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.

## Full collisions and causal prefix ambiguity

Rapid vertical scan versus authorized vulnerability scanner and rapid horizontal
scan versus authorized asset inventory are two **complete 32-event collisions**:
identical entire TrafficEvent metadata, complete runtime feature sequences and
model vectors. Their control provenance/authorization differs outside observations.
No lexical feature, fan-out threshold or model acting only on those same inputs
can distinguish each pair deterministically.

Service discovery is a different finding: its **24 events** equal the first 24 of
the 32-event horizontal positive in raw metadata, runtime features and model
vectors. It is a prefix collision, not identical complete sessions. Event 10 cannot
use the eventual 24/32-event lengths; inventing a completion-length classifier
would be a new unvalidated experiment. No such rule is added.

On this tiny frozen five-positive/six-benign matrix only, the two complete pairs
also establish a gate conflict. Zero benign FPs requires missing both paired
positives, so even perfect recognition of the other three gives recall at most
3/5 = **60%**, below 80%. At recall >=4/5, at least one matched control must alert:
FPR at least 1/6 = **16.67%**, with best precision no greater than 4/5 = **80%**.
These are bounds for deterministic decisions on these identical controlled
observations, not field-performance estimates or a claim about all passive data.

## Causal windows and rule/model distinction

The diagnostic independently checks destination-host count, port count and SYN
observation fraction at every causal prefix, without prediction/training.
First fan-out >=10 is guard eligibility, not a new model decision; >=20 is rule
eligibility, not necessarily an emitted rule alert after model/dedup effects.

- Rapid vertical/horizontal/mixed and their matched high-fan-out controls reach
  the guard at event 10/0.9s and the rule at event 20/1.9s.
- Slower vertical at 500ms reaches guard 10/4.5s and rule 20/9.5s; maximum ports
  in an inclusive ten-second window is 21.
- The 2,000ms horizontal positive reaches at most **six hosts**, never guard ten
  or rule twenty. That supports the already recorded FN as a window-coverage
  limit. No longer history or special demo interval is introduced.
- Scheduled monitoring likewise reaches six hosts; the admin check has nine
  ports and browsing has at most three hosts/two ports. They remain existing hard
  controls, not dropped observations.

SYN fraction denotes observed metadata flags, not successful/failed handshakes.
Adding SYN as a condition would not separate the two matched full pairs, whose
SYN observations are identical. No active verification, authorization lookup,
return path or graph correlation is introduced.

## Quality, testing and freeze

Historical counts are unchanged: **TP4/TN3/FP3/FN1**, precision 57.14%, recall
80%, benign FPR 50%. The original recall >=80%, precision >=95%, FPR <=2% and
before-completion conditions are not weakened. There is no newly accepted recon
candidate. The legacy baseline remains unchanged with disclosed intent limitations.

Added **22 exact diagnostic tests** covering causal maxima, ten/twenty boundaries,
slow-window misses, full-vs-prefix distinctions, invalid inputs, no prediction/
training in traces, report label/history integrity and scoped FP-only replay.
The first broader run found one obsolete UDP diagnostic test that intentionally
used `RECON` as an invalid selector. Since this selector is now supported, it was
updated to a permanently invalid name and strengthened to forbid any file read
before rejection. This changes no detector gate or UDP behavior.

After correction, the focused run passes 23 tests and the combined recon/baseline/
UDP/C2/spoof diagnostic/regression run passes **86 tests in 2.58s**. These are
targeted diagnostics, not a new full backend or frontend build. No shared runtime
code/dependency changed. Source/record pins and protected integrity are recorded
in `verification/recon-observability-20261018/` along with the exact diagnostic
report and tests log. No new accuracy, throughput or inference-cost claim is made.

## Smallest next action and stop

Do not implement another threshold/model trial on this matrix. Qualify one
independently labelled authorized/unauthorized lab pair with matched TCP service,
fan-out/rate and original timestamps, and establish whether any independently
justified, already supported passive context can actually separate it. Authorization
labels/addresses/scenario IDs must not become shortcut predictors. Otherwise an
explicit claim/scope decision is required; the frozen gate is not silently changed.

This diagnosis is frozen. Under continuous-work authorization, the next independent
package is **T25 possible-exfiltration observability diagnosis**, on already exposed
development evidence only. No reconnaissance experiment or model promotion starts.

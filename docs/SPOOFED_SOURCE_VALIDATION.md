# Spoofed-source flood indicators — preregistered controlled audit

## Design frozen 30 September 2026, before constructing or scoring cases

The unit is one externally labelled, isolated synthetic UDP metadata stream,
processed in timestamp order by a fresh production `Pipeline`. The ground
truth records whether addresses were deliberately forged by the controlled
generator or belong to authorised clients. This provenance is **never** a
predictive input. For positives, one simulated emitter assigns the visible
source addresses; for negatives, separate authorised actors own them. These
are metadata simulations, not a claim that actual forged packets were
captured. No packet is sent, no source is probed, and no return path
is assumed. The existing detector has only a generic `DDOS` class; it does
not emit a spoofed-source subtype. This audit will score (a) that existing
alert and (b) a fixed, diagnostic-only subtype predicate. It will not enable
the predicate in runtime or change the frozen model artifact.

The diagnostic predicate is fixed now: target UDP packet rate >=1,000/sec in
the existing ten-second window, >=16 observed source identities, packet-
weighted source entropy >=3.5 bits, singleton-source fraction >=0.75, and
target share of observed packets >=0.8. A singleton is a source with exactly
one **metadata observation/flow summary** in the causal ten-second window;
this is not a claim that it sent only one packet or that it was spoofed.
Compute source count and entropy from the existing bounded target window,
and singleton fraction from the same target's causal observation history.
Cases are limited to <=64 identities, below the runtime target limit of 256.
Also report target packet/sec, observed flow summaries/sec, packet-weighted
entropy, unique source count, singleton fraction and destination
concentration independently from each scenario's metadata. Counts and
fractions are estimates of what this enclave observed, not population facts.

The **four positive** controlled generators are: 32 forged one-shot sources,
64 forged one-shot sources, 32 forged sources each reused across summaries,
and 32 forged sources mixed with unrelated destinations. The **six benign**
generators are: 32 genuinely distributed one-shot clients with identical
visible metadata to the first positive; a 64-client flash crowd identical to
the second; 32 genuinely distributed repeat clients identical to the third;
32 one-shot authorised telemetry clients; high aggregate volume spread across
destinations; and low-rate diverse clients. Identical positive/negative
metadata pairs intentionally test whether source provenance is identifiable
from the permitted fields. Scenario names and labels stay outside the
pipeline. All streams are flow-summary simulations, so this is a functional
metadata audit, not raw-packet or production accuracy.

For each mechanism, a TP requires its first positive indication before the
last event; no early indication is FN. Any indication on a benign scenario
is FP, otherwise TN. Acceptance of a *spoofed-source-specific* runtime
indicator would require recall >=80%, precision >=95%, benign-scenario FPR
<=2%, and no false claim that passive observation proves forgery. With four
positives and six negatives these inequalities require TP=4, FP=0. The
indicator must also distinguish the three matched benign cases; if it cannot,
the feature representation is insufficient for the subtype regardless of
aggregate counts. Every report must give exact TP/TN/FP/FN, first indication
position, feature values, and the small denominator. No gate is relaxed
after results are seen; no reserved or public mixed-label capture is opened
for tuning. A failed diagnostic predicate stays disabled.

Permitted wording is **“consistent with suspected spoofed-source flood”**
or a similarly qualified expression. Neither the existing generic `DDOS`
alert nor this audit may describe an address as proven forged. The five
passive indicators can describe concentration and churn, but cannot verify
address ownership. Synthetic performance is not a field-generalisation
claim.

## Results and decision

**Not verified; diagnostic indicator remains disabled.** The fixed audit in
`datasets/validate_spoofed_source.py` produced
`ml/spoofed_source_validation.json`, with source SHA256s, visible-stream
SHA256s, first-indication positions, feature snapshots and both confusion
matrices. The existing generic `DDOS` alert and the diagnostic-only predicate
had the same scenario outcome:

| Mechanism | TP | TN | FP | FN | Precision | Recall | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing generic `DDOS` | 4 | 2 | 4 | 0 | 50.0% | 100% | 66.7% | 66.7% |
| Fixed suspected-spoof predicate, **not deployed** | 4 | 2 | 4 | 0 | 50.0% | 100% | 66.7% | 66.7% |

The four forged-source scenarios first met the diagnostic predicate at
events 25/32, 50/64, 25/128 and 31/40, respectively, before completion.
The matched 32-client, 64-client flash-crowd and 32-client repeat scenarios
met it at exactly the same positions. Authorised telemetry also met it at
25/32. The dispersed-target and low-rate diverse scenarios did not. These
are **four of six benign false positives** on a deliberately hard, tiny
controlled set; the frozen precision/FPR gate fails. The three matched
positive/negative pairs have identical hashes of all visible event fields.
No deterministic function of these passive fields can distinguish the paired
ground truths, regardless of a different threshold.

Feature evidence at the first indication illustrates the overlap:

| Pair | Target packets/sec | Flow summaries/sec | Unique observed sources | Source entropy | Singleton fraction | Target concentration |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Forged 32 / genuine distributed 32 | 1,000 | 2.5 | 25 | 4.64 bits | 1.00 | 1.00 |
| Forged 64 / flash crowd 64 | 1,000 | 5.0 | 50 | 5.64 bits | 1.00 | 1.00 |
| Forged repeat 32 / genuine repeat 32 | 1,000 | 2.5 | 25 | 4.64 bits | 1.00 | 1.00 |

The repeat streams reach the rate floor before any source repeats; their
singleton fraction is 1.00 **at the causal indication**, then falls to 0 at
completion. Using the completed stream to suppress the early alert would
leak future observations. In the mixed-source positive, target concentration
is 0.806 at indication and 0.800 at completion; in the dispersed benign case
it is 0.031 at completion. Thus concentration can reject dispersed volume,
but cannot distinguish the matched flash crowd. All cases remain below the
256-source target identity cap, so source entropy/count are complete here;
larger populations would produce a marked lower bound. Packet rate comes
from aggregate packet counts assigned to flow-summary timestamps, so true
within-flow packet timing is unavailable. “One observation” is not “one
packet,” and singleton fraction cannot establish source legitimacy.

The current runtime still emits only generic `DDOS`, never a spoofed-source
subtype or proof of forgery. The diagnostic-only wording is **“consistent
with suspected spoofed-source flood”**; it was not enabled because it fails
the gate. No model, detector threshold, raw dataset or alert history changed.
The evaluation script's first draft recorded final target concentration at
the last target event rather than after later background events. That
reporting error was corrected before saving this final report, and a
regression checks the dispersed case's final 1/32 concentration. It did not
change any first-indication decision or confusion count.

The smallest justified next step for this subtype is to obtain independent
lab provenance or another passive signal that actually separates forged
from genuinely distributed clients, then preregister a new evaluation.
Source entropy, source count, singleton fraction, target concentration and
packet/flow rate alone cannot validate source forgery. No active verification
is proposed.

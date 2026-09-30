# Reconnaissance / port-scan validation — frozen design

## Gate recorded before controlled development replay (30 September 2026)

The existing passive `RECONNAISSANCE` path uses one source's ten-second
destination-host and destination-port fan-out. Its rule fires at 20 distinct
hosts or ports; the frozen synthetic model can fire at ten. The `syn_fraction`
feature is the fraction of recent metadata observations carrying the SYN
flag, not proof of a completed or failed handshake. This task does not alter
the model artifact, other detectors, or the read-only architecture.

Evaluate each independently labelled, timestamp-ordered synthetic metadata
scenario with a fresh production `Pipeline`. A positive is an unauthorised
scan by controlled-generator provenance; benign controls are authorised
operations. Provenance, names and scenario IDs are excluded from detector
features. An alert before the final event is TP; a positive with no early
alert is FN. Any alert on a benign scenario is FP; otherwise TN. Record
first-alert position and time, host/port fan-out, observed SYN fraction,
event rate, ten-second window membership, and rule/ML source. Compare
`Pipeline` evidence with an independent causal reference computed only from
events visible at that point.

The **development** matrix has five positives: rapid vertical port scan,
rapid horizontal host scan, rapid mixed host/port scan, a moderately slower
vertical scan at 0.5-second spacing, and a slower horizontal scan at
2-second spacing. There are six benign controls: an authorised vertical
vulnerability scanner with exactly the same visible stream as the rapid
vertical positive; authorised horizontal asset inventory identical to the
rapid horizontal positive; multi-host service discovery; a scheduled
monitor; a small-port administrative check; and ordinary low-fan-out
browsing. The first two pairs deliberately test the limit of passive
authorization inference. All cases are packet-level metadata observations
(`packets=1`) and require no network traffic or active response.

Acceptance of a reconnaissance claim requires recall >=80% (at least four
of five), precision >=95% and benign-scenario FPR <=2% (therefore **zero**
false positives with six controls). Vertical, horizontal, mixed, and the
0.5-second scan must alert before completion. A first alert must not claim
host/port counts or SYN behavior from future observations. The 2-second
scan tests the explicit ten-second visibility limit; report an FN honestly.
At least ten observed hosts or ports are necessary for the current model
guard, and twenty for the rule. Report the minimum evidence and elapsed
time actually observed. No threshold is changed to fit the demo.

If development fails, do not construct, inspect or score an independent
reserved set. No model or rule is promoted on a failed gate. Synthetic
scenario performance is a functional test, not field generalisation. The
passive stream cannot determine whether a scanner was authorised; any
claim of malicious reconnaissance must acknowledge that limit. No graph
analytics or cross-source correlation is in scope.

## Results and decision

**Unresolved: the frozen development precision and FPR gates failed.** The
reserved evaluation set was not constructed, inspected or scored. The
replay's source hashes, independent per-event fan-out references, first-alert
evidence and scenario verdicts are in `ml/recon_development.json`; the
pre-fix alert-output comparison is retained in
`ml/recon_development_initial.json`.

| Controlled development result | TP | TN | FP | FN | Recall | Precision | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Before and after deduplication fix | 4 | 3 | 3 | 1 | 80.0% | 57.1% | 66.7% | 50.0% |

Rapid vertical, horizontal and mixed scans first alerted at event **10 of
32**, 0.9 seconds after the first observation. The 0.5-second vertical scan
also first alerted at event **10 of 32**, after 4.5 seconds. These were
**synthetic-model-only** alerts at the existing ten-host-or-port guard, with
the independently recomputed ten-second evidence matching runtime:

| First-alert pattern | Distinct hosts | Distinct ports | SYN observation fraction | Events in ten seconds | Ten-second average events/sec |
| --- | ---: | ---: | ---: | ---: | ---: |
| Vertical / slower vertical | 1 | 10 | 1.0 | 10 | 1.0 |
| Horizontal | 10 | 1 | 1.0 | 10 | 1.0 |
| Mixed | 10 | 10 | 1.0 | 10 | 1.0 |

The rule threshold remains twenty distinct hosts or ports; first alerts at
ten come from the frozen synthetic classifier. `syn_fraction` is exact for
these one-packet metadata events but measures observed SYN flags, not
handshake completion. It is not required by the current fan-out rule. The
2-second horizontal scan reached at most **six** hosts in any causal
ten-second window, below even the model guard, and was the one FN. This
window does not support slower scans without a separately validated longer
history. No future traffic contributed to the reference or alert evidence.

The false positives were an **authorised vulnerability scanner**, an
**authorised asset inventory**, and **service discovery**. Each had enough
host/port fan-out and SYN observations to trigger at event 10. The first
two have hashes identical to the corresponding unauthorised scan streams:
passive metadata cannot identify operator authorization. Scheduled
monitoring stayed below the ten-second host threshold; a nine-port admin
check and ordinary low-fan-out browsing were also TN. Tightening the
threshold or adding SYN as a requirement cannot distinguish the matched
authorised scanners, so no such change was made. The synthetic model's
confidence is not a calibrated probability of malicious intent.

One measured output defect was fixed without changing classification: the
old reconnaissance dedup key included destination IP. A single horizontal
scan emitted **23 alerts** and a mixed scan **16** for one source; the
source-scoped key now emits **one** per source within the existing 30-second
dedup interval. The authorised asset-inventory and service-discovery false
positives likewise fell from 23 and 15 repeated alerts to one each, but
remain scenario-level FPs. A regression checks that a second source still
receives its own alert. The alert schema and frozen model artifact are
unchanged.

This task verifies causal fan-out accounting and incremental detection for
the rapid patterns, but **does not verify malicious reconnaissance
classification** against authorised network operations. The smallest next
experiment is to obtain independently labelled authorised and unauthorised
scan sessions with a legitimate passive contextual signal that can separate
them, then freeze a new family/time-separated evaluation. No graph
analytics, cross-source correlation, active probes or inline response were
introduced. These synthetic metrics do not estimate production accuracy.

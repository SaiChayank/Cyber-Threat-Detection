# C2 beaconing — frozen controlled validation design

## Preregistered gate (30 September 2026)

This design was recorded before constructing or replaying the C2-specific
controlled matrix. Existing `FeatureExtractor`, `Pipeline`, synthetic demo
scenario, tests, model documentation, and available dataset inventory were
inspected first. The frozen model artifact is unchanged. No live connections,
DNS lookups, source probes, payload inspection, or special demo interval are
used. Source identity, scenario name and benign/malicious provenance are
labels only, never predictive features.

The unit is a separately labelled, timestamp-ordered metadata scenario with
a fresh production `Pipeline`. A `BOTNET_C2` alert **before** its final event
is a TP for a positive scenario. A positive without an early alert is an FN;
any alert on a benign scenario is an FP, otherwise TN. Record the first-alert
event, elapsed observed time, `history_count`, peer inter-arrival mean/CV,
source destination count/persistence, and whether the indication came from a
rule, synthetic model, or both. Count only controlled provenance labels;
generic botnet/C&C labels from public data do not imply periodic beaconing.

The preregistered **development** matrix has six positives: fixed intervals
of 2.5, 6 and 20 seconds to one persistent peer, 6-second beacons with
deterministic ±10% jitter, 12-second beacons to one persistent peer, and
12-second beacons rotating over two peers. It has eight negatives: a fixed
2.5-second health check with visible metadata identical to the first
positive, a fixed 20-second update agent, a 6-second jittered telemetry
agent, scheduled 60-second polling, 12-second rotating telemetry, irregular
browsing, a short periodic sequence, and an intermittent client. All cases
use 32 events unless the short case explicitly ends sooner. Benign workload
provenance is outside the detector. At least one matched positive/negative
pair intentionally tests whether metadata alone can separate purpose.

The unchanged detection candidate must achieve **recall >=80%, precision
>=95%, and benign-scenario FPR <=2%** on these labelled scenarios, with no
more than one missed positive and **zero** benign alerts given the small
denominators. It must detect at least one non-demo interval, the jittered
case and the rotating-small-set case before completion. Do not claim an alert
before enough causal peer history exists: the current path explicitly needs
at least eight observations for the matched peer. Report minimum event
position and elapsed time. A reserved independent set would be designed,
hashed and frozen separately only after a candidate configuration is fixed;
it will **not** be opened if development already fails. No threshold is
relaxed or interval singled out after seeing results.

The existing model was trained on the synthetic demo feature semantics.
Changing `iat_mean`, `iat_cv`, `history_count`, peer scope or history horizon
for deployed inference would require the same definitions in training and
validation. This task will not silently change those model inputs or retrain
the artifact. A failed candidate remains disabled; the current generic
heuristic may remain but must be documented as unvalidated for C2 intent.
Synthetic scenario metrics are not production/generalisation accuracy.

## Results and decision

**Unresolved; the frozen development gate failed. No reserved C2 evaluation
set was constructed, inspected or scored.** The deterministic replay and
source hashes are in `ml/c2_beacon_development.json`. No rule threshold,
history horizon, model artifact, or demo generator was changed.

| Controlled development outcome | TP | TN | FP | FN | Precision | Recall | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current hybrid runtime | 3 | 6 | 2 | 3 | 60.0% | 50.0% | 54.5% | 25.0% |

The fixed 2.5-second beacon alerted at event 8, 17.5 seconds after the first
observation; fixed 6 seconds alerted at event 8/42 seconds. Both were hybrid
rule/model hits with eight same-peer observations, zero inter-arrival CV and
destination persistence 1.0 in the source's 60-second history. The ±10%
jittered 6-second beacon alerted at event 8/41.4 seconds through the frozen
synthetic model alone: its peer CV was 0.1004, above the rule's 0.05 cutoff.
No earlier C2 alert occurred. The shortest observed alert therefore required
eight peer observations and seven 2.5-second intervals (17.5 seconds);
elapsed time depends on the interval, not an accelerated demo clock.

Fixed 12- and 20-second positives and the 12-second two-peer rotation were
false negatives. The source history expires after 60 seconds, so their
maximum same-peer history counts were only 6, 4 and 3 respectively, below
the current eight-observation guard. For a fixed peer, eight observations
require seven intervals within 60 seconds, limiting this path to intervals
around 8.6 seconds or shorter. Rotation over two destinations halves the
same-peer repetition rate. The rotating source had two destinations in its
60-second history and current-peer persistence 0.5, but the model's existing
`destination_count` feature only spans the latest ten seconds and showed 1.
This feature is therefore inadequate evidence of long-horizon destination
persistence for slow rotation. The demo, training and runtime all use the
same `FeatureExtractor` definitions; their common 2.5-second generator is
too narrow to establish generalisation to slower beacons.

The **false positives** were the 2.5-second health check (event 8, hybrid)
and jittered telemetry (event 8, synthetic-model-only). The health-check
stream has exactly the same hash of all visible metadata as the malicious-
like 2.5-second stream; their timing, sizes, source/destination and peer
features are identical. Even a longer history cannot separate that matched
pair without another genuinely available signal. The update agent at 20
seconds and benign rotating telemetry did not alert, but the corresponding
malicious-like patterns were missed as well. Scheduled polling, irregular
browsing, a seven-event periodic sequence and an intermittent client were
also true negatives. These are small, deliberately hard synthetic scenarios,
not field precision or false-positive estimates.

No safe minimal detector change can make this frozen gate pass: extending
history would address slow-pattern recall but would also strengthen periodic
benign matches; changing the CV threshold or exempting the demo interval
would fit the inspected scenarios. The current generic C2 heuristic remains
as it was, explicitly **not validated** for C2 intent against periodic
clients. No new C2 candidate was enabled. The smallest next experiment is
to collect separately labelled malicious and benign periodic clients with
causal metadata beyond timing that is genuinely available to the passive
runtime, then freeze a family/time-separated evaluation design. A later
candidate can test a longer bounded peer horizon with those same feature
definitions in training and inference; no production claim is justified yet.

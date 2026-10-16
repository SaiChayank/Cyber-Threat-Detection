# T20 / T23 — C2 observability diagnosis

16 October 2026. Baseline `bdffcf0`.
**Diagnostic DoD: PASS. C2 quality: UNRESOLVED; release remains NOT READY.**
No detector, threshold, history horizon, training data, model or activation changed.
No reserved evaluation, new data acquisition, external message or database access.

## Scope and reproducibility

Inspected the frozen C2 validation design; development/release-audit reports;
7 October failure attribution and feature-parity/semantic decisions; current
extractor, Pipeline, model/vector/trainer, scenario generator, TrafficEvent,
packet parser/adapter, tests and completion plans. Existing development labels
are synthetic workload annotations, not independently verified malware sessions.

Extended the existing failure-analysis script with `--group C2`. It opens only
the exposed C2 report/generator, verifies generator/model/stream identity and
labels, and reproduces the two saved false positives until their first target
alert. First event, complete alert evidence and actual attribution must match.
The causal extractor also reprocesses the fourteen exposed feature sequences
without model prediction, verifying saved history maxima/final snapshots and
comparing the four positive/benign pairs sharing a timing generator. Labels and
scenario names are annotations only. No positives were rescored for new quality
metrics. Existing regression tests separately exercise their established fixtures.

Reproduce using a new output filename; existing evidence is never overwritten:

```powershell
.venv/Scripts/python.exe -B -m datasets.analyze_baseline_failures --group C2 --output c2-observability.json
.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider tests/test_c2_observability.py tests/test_c2_beacon_validation.py tests/test_baseline_failure_analysis.py tests/test_udp_observability.py
```

Do not invoke the generator's main function: it overwrites its historical report.
The dated protocol was recorded before this diagnostic replay. The saved report
pins the actual diagnostic/runtime sources and model. The legacy JSON key
`identical_raw_event_pairs` means serialized **TrafficEvent metadata equality**,
not raw PCAP-byte equality.

## False-positive breakdown — reproduced first alerts

- **Health check, fixed 2.5 seconds:** event 8, 17.5 seconds observed delay;
  HYBRID. Rule: peer count 8, IAT mean 2.5 seconds, CV 0. Model top class
  BOTNET_C2, posterior 0.9999999999744447. Its entire supplied event sequence,
  complete runtime features and model vectors equal `beacon_fixed_2_5`.
- **Telemetry, jittered 6 seconds:** event 8, 41.4 seconds delay; ML only.
  Peer count 8, IAT mean 5.914285714 seconds, CV 0.1004087425, so the rule's
  CV <0.05 condition is false. Top class BOTNET_C2, posterior
  0.9999999999903848. This is **not** an identical model-vector pair: the benign
  fixture uses 256 bytes per event versus 130 for the positive. Nevertheless,
  the unchanged model alerts on both in the historical evidence.

These are saturated synthetic-trained posteriors, not calibrated probabilities
of malicious intent. Rules and eligible model hits combine as an OR; HYBRID
records agreement, not an independent proof or calibrated confidence increase.
Removing only the model would not resolve the health-check rule false positive.

The six historical TNs are update-agent-20s, scheduled-poll-60s, rotating
telemetry-12s, irregular browsing, seven-event periodic traffic and intermittent
traffic. The slow benign TNs do not demonstrate intent discrimination: their
matching malicious-like patterns are also missed.

## False-negative breakdown — causal history reproduced, verdicts historical

- **Fixed 20-second beacon:** maximum peer history 4; never reaches 8.
- **Persistent 12-second beacon:** maximum peer history 6; never reaches 8.
- **Two-peer rotation every 12 seconds:** maximum history 3 for either peer;
  mean same-peer interval 24 seconds. Final source history contains two peers,
  but ten-second `destination_count` is 1; observed peer persistence is 0.5.

The source deque retains at most 512 events and expires observations older than
60 seconds. Even without capacity pressure, eight same-peer observations require
seven intervals within that horizon: approximately 8.57 seconds or less for a
fixed peer. Both rule and model C2 alerts are suppressed below eight observations.
The 512-event cap and source LRU bound are additional risks under mixed traffic;
they are not the cause of these sparse development misses.

The shortest **historically observed** positive delay is event 8 / 17.5 seconds.
Fixed 6 seconds requires 42 seconds; jittered 6 requires 41.4 seconds. There is no
single seconds-based latency promise independent of observation interval. These
are capture/event times, not processing or SSE benchmarks.

Retained historical quality: **TP 3, TN 6, FP 2, FN 3; precision 60%, recall
50%, F1 54.55%, benign-scenario FPR 25%.** No before/after quality improvement
is claimed. Recall >=80%, precision >=95%, FPR <=2% and the separate early
jitter/non-demo/small-rotation coverage conditions remain frozen and failed.
No reserved C2 set was constructed or consumed.

## Representation and visibility findings

1. **Hard observability collision:** the health check and fixed-2.5 beacon are
   identical in all supplied metadata. No deterministic rule/model using only
   that sequence can classify both correctly. Longer history cannot add absent
   intent. Do not remove the hard negative or use its scenario name as a feature.
   This is not proof that the aggregate C2 gate is mathematically impossible:
   five of six positives would satisfy recall, allowing this one positive to be
   missed. No such configuration has been demonstrated, and selecting an interval
   exception to suppress the pair would fit the exposed examples.
2. **Three partial collisions:** fixed-20/update, jitter-6/telemetry and
   rotating-12/telemetry differ only in event bytes. All four paired C2 timing-rule
   decision sequences agree. The three non-identical pairs differ in model inputs
   `byte_rate` and `egress_bytes`, plus non-model source-forward byte features.
   Constant-size `size_cv` is zero on each. These are possible size observations,
   not evidence that a 130/256/1024-byte cut is safe. No size cut was tested.
3. **Temporal representation is too narrow for the required slow cases.** The
   eight-observation guard plus 60-second horizon explains the three misses.
   Ten-second fan-out is not long-horizon destination persistence. A longer
   horizon alone would also strengthen benign periodic matches; it is not a
   quality fix by itself. Training/runtime semantics must change together in any
   later authorized feature experiment.
4. **Observation unit is a separate limitation.** `history_count` counts input
   events, not independently reconstructed beacon contacts. The PCAP parser emits
   one forward packet record and the adapter passes that timestamp through;
   summaries enter with one timestamp. These controlled cases equate one event
   with one contact. Packet bursts and mixed summaries need independently labelled
   evidence before claiming equivalent raw-PCAP C2 coverage. No new PCAP was read.
5. **Peer key needs explicit interpretation.** Source history is filtered by
   destination address and port, not source port, transport protocol or a verified
   application/session identity. That may be appropriate for reconnecting clients,
   but can mix distinct observations. Existing all-TCP fixtures do not measure
   this risk; no broader behavioral correctness is claimed or code changed.
6. **Training support is narrow.** The existing trainer uses the same current
   extractor as runtime, but its synthetic C2 generator centers on 2.5-second
   intervals and 120–140 bytes; the benign generator lacks these matched periodic
   applications. Seed separation reuses generator styles, not independent families
   or environments. Lack of diversity/separating evidence is more relevant than
   row-class imbalance; no new training rows or artifact statistics were evaluated.
   Names, addresses and scenario IDs are not model inputs. `fingerprint_risk` is a
   known shortcut in the shared model, but these C2 fixtures supply no fingerprint;
   it does not explain their exact metadata collision.
7. **Historical feature compatibility remains failed.** The prior semantic
   audit records rate/entropy/ratio drift with unchanged names. Current trainer
   sharing the extractor does not establish that the historical GNB artifact was
   trained with current semantics. This diagnosis reproduces specific FP outputs;
   it neither corrects that drift nor establishes generalization or causality of
   individual model inputs. No ablation or threshold sweep was performed.

The main cause is overlapping labels at the visibility boundary plus insufficient
temporal/observation representation and a narrow synthetic model. There is no
evidence that a timing threshold adjustment alone would resolve these failures.
Neither passive periodicity nor a generic botnet label proves C2 intent. No
reputation lookup, reverse-path observation or payload decryption is proposed.

## ONE smallest next experiment — not implemented

**Qualify one independently labelled, matched-periodicity C2/benign development
pair and audit contact-versus-packet separability with existing passive metadata.**

First freeze a source/run manifest before inspecting new values: permitted classic
Ethernet captures, original timestamps and run boundaries, producer-confirmed C2
execution/contact labels and benign application labels. Choose one periodic
benign health/telemetry client overlapping the C2 contact intervals and service;
do not pick an easier irregular control. This is development only, never reserve.
Do not execute attacks or use a generic capture-level botnet label as contact truth.

Then, only after qualification is authorized, compare contact annotations against
the existing forward event timestamps, per-event byte/packet information and
causal peer histories. Establish whether a genuinely visible distinction exists
beyond the current synthetic timing/size assignments, and record missingness.
Labels/application identity remain evaluation annotations, never predictors. This
is a small data/representation experiment, not a new detector or training task.

Stop if permissions, original timing, contact labels or matched benign runs are
unavailable, or if the observations remain indistinguishable. Do not manufacture
contacts from desired alerts or silently reinterpret packets as labelled beacons.
Retain all fourteen controls and failed metrics. Only a justified later feature
experiment could change a bounded horizon or event representation, with exact
training/runtime parity and shared regression checks. Gates stay unchanged.

## Tests, integrity and freeze

Added thirteen diagnostic cases; **41 targeted tests pass** including established
C2, baseline attribution and frozen UDP diagnostic regressions. Coverage includes
full-versus-partial collisions, exact slow/rotating counts, causal prefixes,
invalid order/alignment, C2-only report access, label/history tampering and exactly
16 model calls (two eight-event FP prefixes; no positive quality predictions).
No detector bug was fixed. No shared runtime/frontend change, so a new full backend
or frontend build is not needed for this offline diagnostic; the preceding
455-test/typecheck/build evidence remains historical.

Evidence: [protocol](verification/c2-observability-20261016/protocol.md),
[report](verification/c2-observability-20261016/report.json),
[tests](verification/c2-observability-20261016/tests.log), integrity and freeze
records in the same directory. Protected runtime, model, schema, data manifests,
original reports/generator and history hashes are checked unchanged. Raw-data paths
are not opened by the diagnostic. No runtime cost or fresh accuracy was measured.

Freeze this diagnostic implementation, tests, evidence and decision. The existing
legacy C2 heuristic remains active but unvalidated for intent; failed candidates
remain disabled and no new candidate exists. **T23 quality closure is blocked on
qualified separating evidence.** Next is the one development-pair qualification
above, not model training, threshold tuning or reserved scoring.

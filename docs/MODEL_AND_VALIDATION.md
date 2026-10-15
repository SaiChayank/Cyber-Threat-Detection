# Models, runtime features and validation

Audited **2 October 2026** against the current source and saved reports. No model,
threshold, split, gate or detector changed in this documentation task. Measurements
were not rerun. [Report currency](STREAMING_VALIDATION.md) and the
[provenance audit](verification/documentation-audit.json) identify historical revisions.

The subsequent [release audit](FINAL_RELEASE_AUDIT.md) reran the existing SYN,
UDP/spoof, C2, recon, exfil and encrypted controlled fixtures in a fresh checkout.
Their counts below remain unchanged; those new reports now pin the audited source.
Public DGA/tunnel evidence was not rescored. Three inactive public research artifacts
have Windows checkout byte-integrity failures; the active model and both DGA
artifacts retain their checksums. No activation or prediction change occurred.

## What actually runs

**Independent-source review, 14 October 2026:**
[source findings](ENCRYPTED_VALIDATION_SOURCE_REVIEW.md) leave primary validation
and reserve unassigned: no reviewed supplier satisfies frozen metadata/label/format/
benign-control prerequisites. No raw data, inference, model fitting, feature or gate
change. Encrypted training stays BLOCKED and failed candidates remain disabled.

**Source/family-aware design freeze, 14 October 2026:**
[plan](ENCRYPTED_COVERAGE_PARTITION_PLAN.md) records explicit training-development
membership and the independent framework/source, benign application and shortcut
controls required before fitting. Primary validation/final datasets are absent;
empty roles are not a passing final split. The original scenario gates remain
recall>=80%, precision>=95%, benign-scenario FPR<=2% and alert before completion.
No new feature order, model, inference, quality metric or deployment change follows.
Encrypted training is BLOCKED and failed candidates remain disabled.

**Raw TLS source qualification, 13 October 2026:**
[acquisition](TLS_CAPTURE_ACQUISITION.md) passes a narrow development-only gate on
one original Ethernet TQH-C2 cell: **115 controlled C2 + 467 benign TLS sessions**
have verified UID/tuple/source-time joins and observed native ClientHello indices
and timestamps. This is not classifier evaluation. All positive sessions share
one JA3; source partial gate's H3 balance failed. Independent framework/application
coverage and an eligible reserved design are absent. **Encrypted-model training
remains blocked and failed candidates stay disabled**. No model, runtime feature,
detector, prediction, gate or deployment behavior changed. Selected CIRA SLL/DoH
captures still fail source qualification.

**Continuous follow-up, 12 October 2026:** the
[sample/capture-aware split](ENCRYPTED_SPLIT_DESIGN.md) passes technical zero-overlap
checks but leaves only 14/32 positive-related development rows, one component per
side. Subsequent primary-source checks and a licensed MS JOY development download
do not establish session truth or causal handshake placement. No training or model
promotion follows; existing detector gates and failed-candidate activation remain
unchanged. The project release remains blocked by data/quality prerequisites.

**Encrypted-data feasibility, 12 October 2026:** [audit](ENCRYPTED_DATA_FEASIBILITY.md)
finds available offline ClientHello metadata but weak session labels, completed-flow
timing limits and 544 shared malware sample IDs across historical train/validation.
The public TLS candidate's group split is not sample independent; saved metrics
are not rescored or upgraded. No model is trained/activated; runtime promotion is
blocked pending suitable data and acceptance evidence.

**Encrypted fingerprint sensitivity, 7 October 2026:** the
[offline counterfactual experiment](ENCRYPTED_FINGERPRINT_SENSITIVITY.md) zeroes only
the copied fingerprint-risk model input on existing development scenarios.
Model-only TP3/FP4 becomes TP2/FP3, with worse precision/recall. Original hybrid
alerts remain unchanged; the fingerprint rule still fires. This direction is not
adopted and no candidate is trained/promoted. It is seen-data sensitivity, not
independent encrypted-malware accuracy.

**Baseline failure analysis, 7 October 2026:** [attribution diagnosis](BASELINE_FAILURE_ANALYSIS.md)
reproduces the first-alert evidence for 17 already evaluated benign false-positive
scenarios: 7 ML-only, 4 rule-only and 6 hybrid. Historical positive/FN metrics are
preserved rather than rescored. Exact opposite-label observations and synthetic
shortcuts remain unresolved. No detector, model, threshold or gate changed.

**Offline semantic follow-up, 7 October 2026:** the
[feature-semantic contract preflight](FEATURE_SEMANTIC_CONTRACT.md) verifies the
recorded current definitions separately from historical classifier compatibility.
Current conformance PASS does not conceal the historical FAIL in rates, source
entropy and the observed-zero reverse ratio. Exit 1 is expected; this tool is not
an activation gate wired into startup. No artifact, prediction behavior, threshold
or quality metric changed. It uses controlled metadata without dataset evaluation.

Default `Pipeline()` loads the synthetic Gaussian naive Bayes model and combines
its predictions with rules and category guards. Startup verifies the JSON SHA256
sidecar and exact 20-feature order. Inputs use `log1p`, a 0.03 variance floor and
posterior normalization; ML hits need posterior >=0.8. Rule-only score 0.8 is
heuristic strength. RULE/ML/HYBRID attribution and `confidence_kind` are explicit;
severity is separate. Scores are not calibrated compromise probabilities.

| Artifact | SHA256 | Activation |
| --- | --- | --- |
| `ml/artifact.json` | `4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010` | Active synthetic classifier with runtime guards |
| `ml/dga_v2.json` | `c0314dd5f1fe360db11e2494326fd6e99f267d6e920fa091f6c9fcebc796996e` | Loaded/integrity-checked when present; `runtime_enabled=false` |
| `ml/dga_weighted_candidate.json` | `e81821f753d1e1b71fb5a08ff446467165941db996929767edec008c01c130ca` | Separate disabled candidate, not loaded by default Pipeline |

Public DGA/TLS/CIC research artifacts are inactive. DNS-tunnel candidate is an
opt-in rule configuration; `dns_tunnel_candidate=False` by default. The experimental
DGA rule and spoof-specific diagnostic predicate are not runtime detectors.

Historical synthetic fitting: seeds 1–30, 30 experiments/class, 32 events each,
7,680 training rows; validation 31–40 and test 41–50, each 2,560 rows. Whole experiments
stay in a split, resetting causal features per experiment. The same generator
families and already-inspected test seeds are not independent family holdouts.
Labels, scenario names, filenames and source addresses are not direct predictors.
The single lab fingerprint is a shortcut signal; correlated features can yield
overconfident scores.

`ml/evaluation.json` is a historical classifier report. The 29 September
`ml/runtime_evaluation.json` recorded classifier macro F1 **0.9894827640** validation /
**0.9902547932** test. Its extractor/rate-window hashes differ from current source.
Those numbers are historical synthetic classifier results, **not current hybrid
accuracy**. `python -m ml.train` overwrites the frozen artifact. `--evaluate-only`
does not retrain but overwrites the runtime report. Neither ran for this audit.

## Features and causal state

The frozen 20 inputs are packet/byte rate, source entropy, SYN fraction, peer IAT
mean/CV, host/port counts, domain entropy/total length/digit ratio/bigram surprise,
TXT-or-NULL flag, encrypted flag, size CV, historical source bytes, numeric byte
ratio, reverse availability, lab-fingerprint risk and peer-history count.
Training imports the runtime extractor; retaining feature names after later
corrections does not make old training/evaluation hashes current.

Global rates use one-second buckets and a ten-second denominator; global entropy
weights events, target TCP/UDP entropy weights packet counts. Default source history
is at most 512 events/60 seconds across at most 4,096 sources; fan-out uses ten seconds.
Peer timing matches source, destination and destination port. Average bytes/packet
in a flow summary is not an actual packet-size sequence. Late events are dropped.
Bucket overhang, identity truncation and partial windows are disclosed.

Additional rule/evidence features include explicit initial-SYN counts, target rates,
first-label length, causal DNS history and source-forward byte buckets. Exfil rule/
evidence use accurate 60-second totals, while the frozen classifier's bounded
historical `egress_bytes` input remains unchanged. Missing or explicitly zero reverse
traffic gives `observed_byte_ratio=null`; availability distinguishes those cases.
The classifier's historical numeric placeholder is never reported as an observed
ratio. See [reliability semantics](STREAM_RELIABILITY.md).

## Per-threat implementation and measured results

Controlled counts below are **scenario-level synthetic development/functional
results at the recorded revision**, not field accuracy. TP requires an alert before
completion where specified; any benign alert is FP. Precision=TP/(TP+FP),
recall=TP/(TP+FN), FPR=FP/(FP+TN). Small denominators and visibly identical positive/
benign pairs are material limits. Except the explicitly noted source-matching
reports, later shared-source changes mean these have not been scored on final code.

| Threat / data source | Runtime features and rule/model | Validation and metrics | False positives and limitations |
| --- | --- | --- | --- |
| SYN DDoS: `datasets/validate_syn_flood.py`, packet fixtures and aggregate simulations | Destination TCP rate>=1,000 packets/s AND known initial-SYN fraction>=0.70. Model cannot bypass it. Explicit `syn_packets`, packet-weighted target entropy/count. | `ml/syn_flood_validation.json`: TP6/TN6/FP0/FN0, precision/recall 100%, FPR 0%. Corrected replay of the same controlled matrix; all positives incremental. Recorded functional gate passed; source revision now historical. | High-rate established TCP controls did not alert. Aggregate flags without counts cannot establish SYN share. No field FPR or proof of forged sources/reflection. |
| UDP DDoS: `datasets/validate_udp_flood.py`, floods and benign bulk/DNS/QUIC/telemetry | Destination UDP rate>=1,000 packets/s, required for UDP model hits; byte rate, diversity/entropy, concentration and size evidence. Other IP protocols retain the generic rate rule. | `ml/udp_flood_development.json`: TP4/TN2/FP4/FN0, precision 50%, recall 100%, FPR 66.67%; gate failed, reserved evaluation not opened. | Four high-volume benign cases alert. Amplification-like wording is qualified; passive metadata cannot prove reflection or amplification factor. Generic heuristic remains active, quality unresolved. |
| Suspected spoofed-source flood: `datasets/validate_spoofed_source.py`, controlled truth | Entropy, unique sources, singleton fraction, target concentration and rates were diagnostic features. No spoof-specific runtime predicate enabled; generic DDOS only. | `ml/spoofed_source_validation.json`: generic and disabled diagnostic predicate both TP4/TN2/FP4/FN0, precision 50%, recall 100%, FPR 66.67%. | Genuine distributed clients, flash crowds and telemetry match positives. “Consistent with suspected spoofed-source flood” does not prove forgery; no active verification. |
| C2: `datasets/validate_c2_beacon.py`, periodic/jitter/rotation and benign clients | Same-peer history>=8 for every hit. Rule IAT mean>=1s, CV<0.05; synthetic model may match after the count guard. Destination count is ten-second fan-out, not long-horizon persistence. | `ml/c2_beacon_development.json`: TP3/TN6/FP2/FN3; precision 60%, recall 50%, F1 54.55%, FPR 25%; gate failed. Earliest positive event 8/17.5s. | Health checks and jittered telemetry alert; slow12/20s and rotating peers missed. Timing cannot establish malicious purpose. |
| DGA: UMUDGA public strings, legitimate reference and controlled DNS | Active conservative first-label entropy>=3.5, length>=20, bigram surprise>=0.8. Synthetic DGA hits require the same guard. | Historical public-string regression TP478/TN1000/FP0/FN5518: recall 7.97%, precision 100%, FPR 0%. Weighted experiment's active old-rule validation TP19374/TN15212/FP24/FN60626: recall 24.22%, precision 99.88%, FPR 0.16%. Distinct cohorts, neither reserved. | Misses short/word-based families; unusual legitimate lexical names remain possible FPs. Wrapper tuples/times/sizes are simulated. Disabled candidate results below are separate. |
| DNS tunnelling: `datasets/dns_tunnel_development.py`, A/AAAA/TXT/NULL and benign CDN/cloud/telemetry/discovery/TXT/machine names | Default rule first label>=50 and TXT16/NULL10 flag; synthetic model can also hit an observed DNS name. Multi-label/causal query-history candidate disabled. | `ml/dns_tunnel_candidate_validation.json`: rule-only baseline validation TP0/TN4/FP1/FN5, precision 0%, recall 0%, FPR 20%; candidate TP5/TN5/FP0/FN0, precision/recall 100%, FPR 0%, first query 5/12. Baseline arm suppresses synthetic DNS model hits; not full default-hybrid quality. | Legitimate TXT baseline FP. Five positives/five negatives are development data; no reserved full-snaplen dnscat2/iodine sessions. Formal gate unassessed. Mixed/clipped public captures cannot supply recall. |
| Encrypted-session indicators: `datasets/validate_encrypted.py`, TLS/QUIC-like and benign browser/update/API/application | Encrypted flag plus lab JA3 in peer history triggers rule; synthetic model uses size/timing. Every alert requires encrypted flag. No decryption. | `ml/encrypted_session_validation.json`: TP3/TN6/FP4/FN5, precision 42.86%, recall 37.5%, F1 40%, FPR 40%; hashes match runtime at audit, controlled gate failed. No independent reserved set. | Browser/app and shared-JA3 browser/update FPs; novel-JA3, sparse/no-hello and QUIC misses. Experimental. Single-packet ClientHello/JA3 only; no raw QUIC Initial/JA3S/JA4 or TLS reassembly. |
| Recon: `datasets/validate_recon.py`, vertical/horizontal/mixed/slow scans and authorized controls | Source ten-second host/port fan-out>=20 rule; model needs>=10. SYN is evidence, not authorization. Source-scoped30s dedup preserves one sweep record. | `ml/recon_development.json`: TP4/TN3/FP3/FN1; precision 57.14%, recall 80%, F1 66.67%, FPR 50%; gate failed. Fast first event 10/0.9s; 0.5s-spacing first event 10/4.5s. | Authorized scanner, inventory and service discovery FPs; 2s-spacing scan FN. Passive metadata cannot infer permission. |
| Possible exfiltration: `datasets/validate_exfil.py`, large/sustained/one-way/bidirectional transfers and matched benign | Source-forward 60s volume>20,000,000 bytes rule; synthetic model may alert earlier. Ten-second byte rate and current-event ratio only with observed reverse metadata. | `ml/exfil_development.json`: TP4/TN2/FP4/FN1; precision 50%, recall 80%, F1 61.54%, FPR 66.67%; gate failed. Stress first event 801/1000 at 20.025MB. Source hashes match runtime. | Backup/upload/sync/replication FPs; slow transfer FN. Source-forward is not necessarily Internet egress; content/intent unverified. Missing reverse stays unavailable. |

Detector-specific protocols in `docs/*VALIDATION.md` preserve frozen gates and
first-alert evidence. Source mismatches are catalogued rather than erased.

## Disabled DGA candidates and unchanged gates

Existing `dga_v2`, threshold 0.9: inspected development comparison TP46503/TN14659/
FP251/FN14074, precision 99.46%, recall 76.77%, domain FPR 1.68%. Separate benign-DNS
FP275/11731 =2.34%. Those families/references influenced development; recall and
separate-DNS gates failed. Candidate disabled.

One weighted candidate, threshold 0.85, fit only frozen training and tuned only
validation. Exact portable first-label 2-/3-grams and ten lexical fields from
`ml/dga.py`; no family/source/file/scenario predictors. Validation TP74242/TN14958/
FP278/FN5758: precision 99.63%, recall 92.80%, F1 96.09%, domain FPR 1.82%. Portable
scorer error<=2.22e-16 on 201 validation samples. Weighting increased FP268→278 at
selected thresholds; it did not demonstrate FP reduction.

Weighted final reserved domain and separate benign-DNS sets were not materialized.
Their metrics are unmeasured, not passing. Frozen final gates remain recall>=80%,
precision>=95%, domain FPR<=2%, separate benign-DNS FPR<=2%. No new training,
reserved inspection or promotion occurred. See [weighted result](DGA_WEIGHTED_CANDIDATE.md)
and [protocol](DGA_EVALUATION_PROTOCOL.md).

## Demo and performance are separate evidence

[Demo](FINAL_DEMO.md): eight controlled standalone scenarios plus ALL, each required
threat incremental, benign zero alerts; combined256 events/15 alerts. No independent
accuracy claim. Latest source-matching measurements, 1 October: core+SQLite
5,649.91 metadata events/s and p95 0.8416 ms; loopback API-to-SSE p95 240.27 ms,
100/100 complete records. Neither is raw-capture-to-browser throughput.

DNS visibility excludes DoH/DoT QNAMEs, LLMNR5355, clipped questions and segmented
DNS/TCP. QUIC metadata can be supplied but is not handshake-extracted. Raw reverse
packets are separate observations, not fabricated reverse-flow summaries. Physical
diode certification, field calibration, production auth and malicious-intent proof
are outside the implemented evidence.

## Encrypted source follow-up — 13 October 2026

[Publisher/JOY semantic inspection](ENCRYPTED_SOURCE_FOLLOWUP.md) confirms that the
current public MS listing contains derivatives, with no raw capture file. Its
packet summaries count payload bytes and omit some packets; they cannot silently
stand in for runtime IP-packet events. Explicit per-session labels and causal
ClientHello placement remain unverified. No training, inference, new model metrics,
reserved-data inspection or promotion occurred. Archived failed candidates remain
disabled. This diagnostic pass and the independent UI refinement do not resolve
the encrypted-session quality gate.

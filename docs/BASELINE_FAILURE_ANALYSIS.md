# Active baseline failure analysis — 7 October 2026

**Definition of Done: PASSED for failure analysis only. Detector quality remains
unresolved; release is NOT READY.** No gate was relaxed, detector/model changed,
candidate enabled, training performed or reserved evaluation inspected.

## Inspected and method

Inspected Pipeline rules/guards/combination/dedup, current causal extractor,
frozen GNB/feature contract, five existing development generators, their original
protocols, the release-audit reports, and separate suspected-spoof evidence.
The model SHA256 remains
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.

The diagnostic reconstructs only previously evaluated generators, verifies their
saved source pins allowing LF/CRLF checkout conversion, checks existing stream
hashes where supplied, and runs the actual Pipeline until the first target alert
on each recorded false positive. A wrapper observes its real features/prediction;
it returns the original prediction unchanged. First-alert position and all saved
evidence must match, otherwise the diagnostic stops rather than relabelling.
UDP's old report omits `detection_source`; this replay establishes it explicitly.

**All 17 recorded false-positive first alerts reproduced exactly.** Their source
breakdown is **7 ML, 4 RULE, 6 HYBRID**. HYBRID means both independently matched
at that event; it does not mean agreement removed uncertainty. RULE here means
the target class was not the thresholded top model prediction at that event,
not that the model never contributed later. The recorded model posterior is for
the **top predicted class**, not necessarily the requested threat, and is uncalibrated.

Positive/false-negative quality results below are retained historical values,
not new evaluations. Feature-sequence hashing of existing cases checks exact
representation collisions only. No rule/model ablation was performed. Report
runtime source hashes predate recovery staging; the new diagnostic records current
hashes and verifies these specific FP outputs rather than relabelling old reports
as measurements of all current behavior. DGA, tunnelling and SYN gates are untouched.

Reproduce, using a new output filename:

```powershell
.venv/Scripts/python.exe -B -m datasets.analyze_baseline_failures --output baseline-failures.json
.venv/Scripts/python.exe -B -m pytest tests/test_baseline_failure_analysis.py tests/test_c2_beacon_validation.py tests/test_recon_validation.py tests/test_exfil_validation.py tests/test_encrypted_visibility.py -q -p no:cacheprovider
```

## Existing confusion counts — not refreshed quality claims

| Controlled matrix | TP | TN | FP | FN | Precision | Recall | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UDP | 4 | 2 | 4 | 0 | 50% | 100% | 66.67% |
| C2 | 3 | 6 | 2 | 3 | 60% | 50% | 25% |
| Recon | 4 | 3 | 3 | 1 | 57.14% | 80% | 50% |
| Possible exfiltration | 4 | 2 | 4 | 1 | 50% | 80% | 66.67% |
| Encrypted indicators | 3 | 6 | 4 | 5 | 42.86% | 37.5% | 40% |

These are small, already inspected controlled scenario matrices. Cases overlap
and labels describe lab provenance, so do not pool them into overall accuracy,
independent generalization or production FPR. Existing predeclared gates remain
unchanged and failed. There are no before/after quality gains in this task.

## False-positive attribution

| Benign scenario | First event | Source | Decisive finding |
| --- | ---: | --- | --- |
| `benign_quic_bulk` | 10,000 | HYBRID | Target UDP rate 1,000/s; one source, 1,200-byte packets, concentration 1. Neither volume nor the GNB proves maliciousness. |
| `benign_dns_queries` | 10,000 | HYBRID | Target rate 1,000/s, 32 sources, 80-byte questions; legitimate DNS remains a rate-rule hit. |
| `benign_video_bulk` | 3 | HYBRID | Target rate 1,200/s, 1,200-byte summary means; same full GNB feature sequence as `flood_single_large`. |
| `benign_telemetry_many` | 25 | HYBRID | Target rate 1,000/s, 25 sources at first alert, 256-byte means; diversity does not establish attack intent. |
| `health_check_2_5` | 8 | HYBRID | Mean 2.5s, CV 0, history 8; full metadata identical to the fixed 2.5s positive. |
| `telemetry_jitter_6` | 8 | ML | CV 0.100409 fails the rule's <0.05 cutoff, but the GNB alone predicts C2 with a posterior rounded to 1. |
| `authorised_vulnerability_scanner` | 10 | ML | Port fan-out 10, SYN fraction 1; model's >=10 guard allows an alert before the >=20 rule. |
| `authorised_asset_inventory` | 10 | ML | Host fan-out 10, SYN fraction 1; purpose/authorization is unobservable. |
| `service_discovery` | 10 | ML | Host fan-out 10; same early fan-out behavior as scanning, without requiring the rule. |
| `cloud_backup` | 6 | RULE | 24MB observed forward bytes in the source window; top model is BENIGN. Rule overrides that benign prediction. |
| `legitimate_large_upload` | 1 | RULE | 25MB one-way volume; top model is BENIGN; content/intent unavailable. |
| `synchronization` | 1 | ML | Only 4MB so volume rule is false; observed reverse availability and ratio 40 coincide with the synthetic exfiltration shortcut. |
| `replication_deployment` | 5 | RULE | 25MB window total; model top class BENIGN with posterior 0.996379. |
| `browser_tls` | 15 | ML | No lab fingerprint; size CV 0.726556 / IAT CV 0.732884 yield encrypted-malware posterior 0.857406. |
| `ordinary_encrypted_app` | 15 | ML | Same vector sequence as `quic_variable`, an oppositely labelled positive. |
| `browser_shared_ja3` | 1 | RULE | The lab fingerprint alone activates the rule. Top model is C2, not encrypted malware, and its C2 history guard prevents an early C2 alert. |
| `update_shared_ja3` | 1 | HYBRID | Lab fingerprint activates the rule and GNB; neither implies the shared client fingerprint belongs to malware. |

Seven model-only alerts show that the hybrid system is effectively an OR of
eligible model hits and rules, with category guards. Rule-only controls show why
retraining alone cannot fix all cases. Removing model-only hits would also alter
true detections and is not an experiment performed here. Later rule matches may
be hidden by deduplication; first-source totals are not whole-session ablations.

## False-negative breakdown

| Missed scenario(s) | Saved evidence | Cause supported by evidence |
| --- | --- | --- |
| C2 `beacon_fixed_20` | Maximum peer history 4 | 60-second retention cannot satisfy the >=8 history guard. |
| C2 `beacon_persistent_12` | Maximum peer history 6 | Same history/guard conflict, despite perfect periodicity. |
| C2 `beacon_rotate_12` | Maximum peer history 3 per destination, mean peer interval 24s | Splitting evidence by peer further reduces retained history; not a special demo-interval problem. |
| Recon `slow_horizontal_scan` | Maximum hosts 6 in ten seconds | Below both >=10 ML guard and >=20 rule; causal rate-window coverage limit. |
| Exfil `slow_sustained` | 20MB observed in sixty seconds, reverse unavailable | Rule requires strictly >20MB; longer transfer lifetime is not accumulated beyond the causal window. Missing reverse is not invented as zero. |
| Encrypted `novel_tls_stable`, `novel_tls_variable`, `tls_no_hello`, `quic_stable`, `tls_sparse` | Each has zero saved target model/rule hit events | No lab fingerprint rule match; synthetic model does not recognize these timing/size patterns. Absent ClientHello/QUIC fingerprint visibility also limits inference. |

UDP has no FN in its four small controlled positive scenarios; that is not proof
of coverage of real UDP attacks. The ten FNs above were not newly rescored.

## Data, representation, rules/model and visibility

**Data/separability:** the health check, two authorized scan pairs and four
legitimate transfer pairs have identical full metadata to their oppositely labelled
positives. The separate spoof report also has three identical positive/benign
stream hashes (owned addresses versus claimed forged provenance). Any deterministic
metadata-only classifier must produce the same decision for each exact pair.
These are intentional hard controls demonstrating purpose ambiguity, not evidence
of train/test leakage. Do not remove them to make a gate pass.

**Representation:** the bulk-video/UDP-flood pair differs in destination port but
has identical full GNB input sequences. Several encrypted positive/benign cases
also collide in all 20 inputs despite differing transport, non-lab JA3, addresses
or observation day. Full raw equality proves an observation limit; feature-only
equality proves a representation limit, not that every passive field is identical.
No addresses, labels, capture IDs or dates should become shortcut predictors.

**Rule thresholds:** rate alone, volume alone, periodicity alone and exact lab
fingerprint are sufficient for some active rules. They detect observations but
cannot prove intent. Raising thresholds cannot separate identical opposite-label
pairs; lowering them to catch slow misses would broaden the observed overlap.
Threshold changes are neither justified nor made here.

**Model:** synthetic benign examples do not adequately cover these hard controls.
Strong, uncalibrated top posteriors on legitimate traffic and the established
reverse-availability/fingerprint shortcuts undermine confidence. Model-only C2
and recon hits can alert where their stricter rules do not match. The exfil
reverse-availability shortcut is supported by the artifact/paired inputs, but this
task has not ablated it to establish its isolated numerical contribution.

**Visibility:** authorization, ownership of source addresses, confidential content
and malware intent are not directly visible. Encrypted payloads remain encrypted;
raw QUIC fingerprints remain unsupported, and no active lookup/probe is added.
Spoof diagnostics stay disabled. The legacy active baseline stays unchanged with
disclosed failures; disabled research candidates are not promoted.

## Verification, freeze and one next experiment

Added only `datasets/analyze_baseline_failures.py`, eleven diagnostic regression
cases, this document and dated evidence; completion/model docs link this finding.
**39 targeted tests passed**, including existing C2/recon/exfil/encrypted regressions.
No shared runtime/frontend behavior changed, so full backend/build was not rerun;
the preceding recovery recheck remains 268 backend tests and TypeScript/build pass.

[Attribution/overlap report](verification/baseline-failure-analysis-20261007/report.json)
and [test log](verification/baseline-failure-analysis-20261007/tests.log) freeze
scope and measurements. Existing numerical reports are preserved. This diagnosis
does not estimate improvement, runtime cost, independent accuracy or calibrated
probabilities, and it does not clear a release blocker.

Recommend **one offline encrypted `fingerprint_risk` sensitivity ablation** on
the existing 18 controlled development scenarios: keep all observed events,
features, frozen model and thresholds fixed, and compare the GNB's predictions
with only that feature counterfactually set to zero. Record changes in target
hits for lab positives, shared-fingerprint benign controls and novel fingerprints;
retain observed versus counterfactual values explicitly. Do not alter the rule,
artifact or runtime, fit a candidate, inspect reserved data or claim a passing
quality gate. This isolates one demonstrated shortcut at minimal cost and leaves
rule-only failures visible. **The experiment has not been implemented or run.**

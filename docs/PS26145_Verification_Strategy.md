# PS26145 — Verification Strategy
**Scope:** The full test plan for the system already designed — no new architecture, features, or components. This document directly closes the "missing testing strategy" gap (B3) and the "missing tests" gaps (E1–E4) flagged in the final pre-blueprint audit, and provides the concrete throughput commitment that closes G1 from that same audit.

---

## 1. UNIT

### Parsers
- Per input format (PCAP, NetFlow, IPFIX, sFlow): a fixed set of known-good sample records, asserting every canonical field (per the data-model task) is extracted correctly.
- **Malformed-input tests per format:** truncated packet/record, corrupted header, unsupported protocol/version, zero-length payload, IPv6-vs-IPv4 field handling — each must route to the dead-letter/quarantine path (per the runtime-pipeline design) without raising an unhandled exception.
- **Boundary tests:** minimum-size valid packet, maximum-size record, a record with every optional field absent — confirming the parser distinguishes "absent" from "zero."

### Features
- **Streaming-primitive correctness, tested against known values:** Welford mean/variance against a hand-computed reference series; HyperLogLog cardinality estimate within its documented error bound for a known-cardinality input set; Count-Min Sketch frequency estimate within its documented error bound; Bloom filter false-positive rate measured empirically and confirmed within the configured target; entropy calculation against strings with known Shannon entropy values; the n-gram score against a small fixed reference table with known expected outputs.
- **Causality tests:** feed events deliberately out of the pipeline's normal arrival order (simulating jitter within the allowed-lateness grace period) and assert a feature's value at time `t` never reflects any record timestamped after `t` — a direct test of the feature-engineering task's core causality rule.
- **Window-expiry tests:** confirm short-window state (DDoS/recon) is evicted after its window closes, and confirm long-window state (C2/exfiltration) maintains only bounded sufficient-statistics memory regardless of how long a key stays active — a memory-shape assertion, not just a value assertion.
- **High-cardinality tests:** feed a synthetically large number of distinct keys (source IPs, domains) and confirm memory usage for the relevant sketch/structure stays within its configured bound rather than growing linearly with input cardinality.

### Detectors
- **Rule-threshold boundary tests, per rule:** a feature value just below, exactly at, and just above each documented threshold (per the rule-baseline task), confirming the decision flips exactly where documented.
- **ML-wrapper determinism tests:** given a frozen model version and a fixed feature vector, confirm the same output every time (guards against any accidental non-determinism in preprocessing/inference code, separate from the model's own trained behavior).
- **Detector-failure isolation test:** force an exception inside one detector's code path and confirm the pipeline continues processing subsequent events and other detectors are unaffected — directly testing the runtime-pipeline's detector-failure-isolation design.

---

## 2. ML

### Model Validation
- Re-run, as an automated check, the full evaluation the model-development methodology specifies: Macro F1, per-class precision/recall/F1, FPR, PR-AUC, ROC-AUC, and calibration metrics (Brier score, ECE) against the frozen test split for every detector.
- **Pass condition:** results meet or exceed the MVP-stage team targets already set in that methodology (Macro F1 ≥ 0.70, per-class recall ≥ 0.65, tiered FPR targets, PR-AUC ≥ 0.70 for classifier-primary detectors, ECE ≤ 0.15) — this test suite is the automated gate for those targets, not a new target-setting exercise.
- **Configuration-holdout and temporal-holdout results are reported and gated separately**, per the methodology's own scenario-separation design — a detector passing on the temporal holdout but failing on the configuration holdout must be flagged as memorizing specific attack signatures, not passed silently.

### False Positives
A dedicated suite using **known benign patterns already identified as likely false-positive triggers** across the rule-baseline and model-development tasks — each must be confirmed to NOT cross the alert threshold (or to alert at a rate within the detector's committed FPR budget):

| Detector | Benign FP-risk pattern under test |
|---|---|
| DDoS | Flash-crowd/backup-burst traffic at comparable volume to the flood threshold, but organically shaped |
| C2 Beaconing | NTP synchronization and OS/telemetry heartbeat traffic at regular intervals |
| DGA Domains | CDN/load-balancer auto-generated, high-entropy-looking subdomains |
| DNS Tunnelling | Heavy legitimate TXT-record usage (SPF/DKIM lookups) |
| Encrypted-Session Malware | Legitimate low-bandwidth IoT/monitoring-agent TLS sessions with naturally regular timing |
| Reconnaissance | The organization's own authorized vulnerability-scanner run |
| Data Exfiltration | A legitimate large backup/cloud-sync upload to an already-established destination |

### Temporal Leakage
- **Automated split-integrity check:** confirm no `experiment_id` appears in more than one of train/validation/test.
- **Chronological-order check:** confirm the temporal holdout's experiments are genuinely later-dated than the bulk of training experiments (per the methodology's walk-forward preference), flagging any exception that was logged as allowed.
- **Static-reference-table build-date check:** assert the DGA n-gram model and any known-fingerprint list were built only from data timestamped before the evaluation-period cutoff — a direct, automatable test of the leakage-prevention discipline stated (but not previously verified) in the feature-engineering and model-development tasks.

---

## 3. INTEGRATION

- **Full-chain golden-file test:** a small, fixed synthetic pcap/flow fixture with a known expected alert output run through the entire chain (Passive Ingest → Parser → Normalizer → Streaming State → Feature Extraction → Detection → Confidence/Severity → Evidence → Alert Output), asserting the exact resulting alert record matches the expected fixture.
- **Malformed-event non-crash test:** inject a malformed record mid-stream and confirm it reaches the dead-letter path without halting or corrupting downstream state for other, valid events in the same run.
- **Deduplication test:** replay the same underlying condition (e.g., a sustained flood) and confirm exactly one evolving alert is produced per the dedup/cooldown/escalation logic already designed, not one alert per triggering event.
- **Hybrid-combination test:** construct a scenario where both a rule and its corroborating classifier fire on the same flow, and confirm exactly one alert is emitted with `detector_type = hybrid` and the max-of-both confidence combination applied correctly.

---

## 4. SYSTEM

### Backend
- **API contract tests** for every endpoint in the backend design: correct response shape, correct status codes for valid/invalid input, correct filter behavior (`threat_class`, `severity`, `min_confidence`, date ranges) against a seeded test database.
- **Authentication/authorization enforcement tests** (cross-referenced with the security review): every protected endpoint rejects unauthenticated requests, accepts authenticated ones.

### Database
- **Schema/migration tests:** confirm all required entities, relationships, and indexes exist as designed.
- **Referential-integrity tests:** confirm foreign-key relationships (`alerts.model_version_id`, `alerts.replay_session_id`, `analyst_feedback.alert_id`) are enforced, including the nullable cases (rule-only alerts, live-mode alerts).

### Dashboard
- **Smoke tests** for every MVP page (Overview, Live Detections, Alerts, Alert Detail): confirm each renders without error against a seeded backend.
- **SSE test:** confirm a connected client receives a pushed alert within an expected short delay of it being ingested by the backend.
- **State-rendering tests:** loading, empty, and error states for each page render as designed (per the SOC-UI task's explicit state definitions) rather than defaulting to a blank or broken view.

### Replay
- **Known-outcome replay test:** start a replay session against a labeled lab experiment with a known expected alert set, and confirm the resulting alerts match within an acceptable tolerance (allowing for legitimate confidence-score variation, not exact-match on every field).
- **Session lifecycle test:** confirm a replay session's status transitions correctly (`starting` → `running` → `complete`), including the failure path (invalid experiment ID) reporting a specific, non-generic error, per the security review's file/PCAP validation design.

---

## 5. SECURITY

This section runs, not redesigns, the test methods already specified in the security review — consolidated here as an execution checklist:

- Authentication: unauthenticated request rejected (401), valid-credential request succeeds.
- CORS: disallowed-origin request lacks exposing headers; allowed-origin request succeeds.
- Input validation: out-of-range/wrong-type parameters return 422, not a server error.
- File/PCAP validation: nonexistent experiment ID, path-traversal-style ID, and corrupted pcap are each rejected distinctly and correctly.
- Secrets management: repository scan confirms no hardcoded credentials; application fails safely on a missing required secret.
- Dependency security: `pip-audit`/`npm audit` run with no unresolved high/critical findings.
- Model integrity: a deliberately corrupted model artifact is detected via hash mismatch and the system falls back to the rule path rather than loading it.
- Dataset integrity: a deliberately altered stored pcap/flow file is detected via hash mismatch and excluded from training/evaluation.
- Audit logging: a failed login, a replay-session start, and a model-version change each produce a corresponding `audit_events` row.
- **Passive-ingest no-return-path test:** run Passive Ingest inside a network namespace with all egress blocked and confirm capture and downstream processing continue functioning identically — the specific test the security review specified but had not yet executed.

---

## 6. ARCHITECTURAL COMPLIANCE

Each of the six properties below gets a specific, falsifiable test — not a design assertion.

| Property | Test |
|---|---|
| **No probe is emitted** | Capture the pipeline's own network activity (via `tcpdump` on every interface the pipeline process can reach) during a full end-to-end test run, and assert zero outbound packets originate from the monitoring/capture-facing interface at any point. |
| **No return path is required** | Static check: confirm the capture interface has no assigned IP address in its runtime configuration. Dynamic check: run detection twice on identical input — once with a hypothetical return route physically available, once with it fully removed/blackholed — and confirm bit-identical detection output in both cases, proving no code path depends on that route existing. |
| **No inline blocking is used** | Static check: scan the ingest and detection code paths for any synchronous "send and wait for response" pattern. Dynamic check: process a replay where all response-direction traffic is entirely absent, and confirm processing throughput and detection results are unaffected — a system depending on inline blocking would stall or degrade here. |
| **TLS/QUIC payloads are not decrypted** | Static check: scan the codebase and its dependencies for any decryption-key handling, private-key loading, or payload-decryption library call anywhere in the ingest or feature-extraction paths. Dynamic check: feed a TLS/QUIC session with no private key ever made available to the pipeline, and confirm JA3/JA3S/JA4 features are still computed correctly and no output field ever contains decrypted plaintext — proving decryption was never needed, not just never used. |
| **Processing is incremental** | Feed events one at a time with artificial inter-event delays into a long test capture, and assert that feature values and (where applicable) alerts appear progressively as events arrive, rather than only after the entire input has been consumed — directly distinguishing this from a batch/end-of-run report. |
| **Alerts appear before stream completion** | Run a multi-minute replay of a sustained attack scenario and assert that at least one alert's `detection_timestamp` precedes the final event's timestamp in that same replay — and precedes the replay session's transition to `complete` status — the specific, falsifiable proof of near-real-time operation the PS requires. |

---

## 7. PERFORMANCE

| Metric | Method |
|---|---|
| **Flows/sec** | Accelerated replay at increasing input rates until queue depths (below) grow unboundedly; the highest sustained rate without unbounded growth is the system's committed throughput figure. |
| **Mbps** | Measured alongside flows/sec on the same test, using the replayed traffic's actual byte volume. |
| **Feature latency** | Time from Normalizer output to Feature Extraction output, per event, reported as p50/p95/p99. |
| **Inference latency** | Time from Feature Extraction output to Detection verdict, measured separately for the rule path, each ML detector, and the hybrid-combination step, since these are expected to differ meaningfully (per the model-selection task's latency comparisons). |
| **End-to-end alert latency** | Time from the underlying event's arrival at Passive Ingest to the corresponding Alert Output emission — the core metric against the PS's bounded-latency requirement, reported as p50/p95/p99. |
| **Queue depth** | Sampled continuously at the three buffering points (ingest buffer, detection-dispatch buffer, alert-output buffer) under sustained load; asserted to stay within their configured bounds. |
| **Dropped events** | Measured and categorized under a deliberate overload test into the three distinct drop types already designed (capture-level, overflow, late-arrival), confirming each is logged distinctly rather than as one undifferentiated counter. |
| **CPU** | Process CPU utilization sampled during the sustained-load test, reported as average and peak. |
| **Memory** | Sampled over a long-duration run (e.g., one hour of continuous replay) specifically to catch unbounded growth — a direct validation that the feature-engineering task's window-expiry and inactive-key-eviction design actually holds under real, extended operation, not just in isolated unit tests. |

**Committed MVP performance targets** (team-set, explicitly not an official SIH-mandated figure, consistent with how the model-development methodology framed its own team targets): sustain at least **2,000 flows/sec** with **p95 end-to-end alert latency under 2 seconds**, zero unbounded queue growth, and stable memory over a one-hour sustained run. This closes the earlier audit finding that no concrete throughput number had ever been committed.

---

## 8. Test Scenarios — Required Threats and Legitimate False-Positive-Prone Behaviors

| Threat | Attack scenario (traffic source, per the lab-architecture task's official tools) | Expected outcome | Paired benign FP scenario | Expected outcome |
|---|---|---|---|---|
| DDoS | hping3 SYN/UDP flood at multiple intensities against the victim VM | Alert, `threat_class=ddos`, correct sub-type | Flash-crowd/backup-burst traffic at comparable volume via the benign generators | No alert (or below committed FPR budget) |
| C2 Beaconing | Sandboxed C2 emulator at fixed and jittered intervals | Alert, `threat_class=c2_beaconing` | NTP sync / telemetry heartbeat traffic at regular intervals | No alert |
| DGA Domains | DGArchive-sourced domain queries across multiple families against the internal fake resolver | Alert, `threat_class=dga_domains` | CDN/load-balancer-style randomized subdomain queries | No alert |
| DNS Tunnelling | dnscat2 and iodine sessions against the internal tunnel-server role | Alert, `threat_class=dns_tunnelling` | Heavy legitimate TXT-record usage (SPF/DKIM-style lookups) | No alert |
| Encrypted-Session Malware | Emulated malicious TLS session with a rare fingerprint and regular packet-size/timing pattern *(contingent on the encrypted-malware data gap being resolved per the final audit's Correction 1)* | Alert, `threat_class=encrypted_malware` | Legitimate low-bandwidth IoT/monitoring-agent TLS session with naturally regular timing | No alert |
| Reconnaissance | Port/host fan-out scan at varying rates against the victim VM | Alert, `threat_class=reconnaissance` | The lab's own authorized vulnerability-scanner run | No alert |
| Data Exfiltration | Large asymmetric outbound transfer to a novel internal destination | Alert, `threat_class=data_exfiltration` | Legitimate large backup/cloud-sync-style upload to an already-established destination | No alert |

Every scenario above is drawn directly from tools and behaviors already named in the lab-architecture and rule-baseline tasks — no new traffic-generation method is introduced here.

---

## 9. MVP Acceptance Criteria

The system is accepted as MVP-ready only when **all** of the following hold:

1. **Functional coverage:** every scenario in §8's attack column produces a correctly-classified alert, and every paired benign scenario produces no alert (or stays within its committed FPR budget) — for all seven threats, **contingent on the final audit's Correction 1** (encrypted-session malware data gap) being resolved; if that correction resolves as a formal MVP descoping instead, this criterion applies to the remaining six threats and the system is accepted as a six-threat MVP with encrypted-malware explicitly documented as future work, not silently omitted.
2. **ML validation gate (§2):** all detectors meet or exceed the model-development methodology's MVP-stage team targets on both the temporal and configuration holdouts.
3. **Integration chain (§3):** the golden-file end-to-end test passes, malformed events are handled without crashing, deduplication behaves as designed, and the hybrid-combination test passes.
4. **System tests (§4):** all MVP dashboard pages render correctly in all three states (loading/empty/error), the SSE live feed delivers alerts within expected delay, and a known-outcome replay session produces the expected alert set within tolerance.
5. **Security checklist (§5):** every MVP-classified control from the security review passes its test, with zero exceptions — this is a hard gate, not a scored average.
6. **Architectural compliance (§6):** all six properties (no probe emitted, no return path required, no inline blocking, no TLS/QUIC decryption, incremental processing, pre-completion alerting) pass their specific falsifiable test — **zero tolerance**, since these are the properties the entire PS is built around, not ordinary quality bars.
7. **Performance (§7):** the committed MVP targets (≥2,000 flows/sec, p95 end-to-end alert latency < 2 seconds, no unbounded queue growth, stable memory over a one-hour run) are met and recorded with actual measured numbers, not projected ones.
8. **Correction 2 from the final audit** (train/serve feature-computation equivalence) has been resolved by the time this acceptance checklist is run — since every number in criteria 2 and 7 is only meaningful once that equivalence is established.

Any single failed criterion above blocks MVP acceptance until resolved — consistent with the project's established BLOCKER-means-not-ready discipline carried over from the final pre-blueprint audit.

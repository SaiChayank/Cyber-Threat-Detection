# PS26145 — Data & ML Readiness Review
**Scope:** Audit only — checking the already-approved canonical schema, streaming features, rule baseline, ML formulation, model selection, and training/validation methodology against each other for consistency, completeness, and constraint compliance. No backend/runtime design happens in this document.

---

## Checklist Walk-Through

### 1. Every detector has the data it requires
- **DDoS, Reconnaissance, C2 Beaconing, DGA Domains, DNS Tunnelling:** **PASS.** Each has a named official-tool data source (hping3/Slowloris; scanning tool; sandboxed C2 emulator + CTU-13 validation; DGArchive; dnscat2/iodine + DoHBrw-2020 validation), traced through to the specific fields each detector's features need.
- **Data Exfiltration:** **PASS**, self-generated (controlled asymmetric transfers) — no external dataset needed or expected.
- **Encrypted-Session Malware:** **FAIL — unresolved.** The dataset-evaluation task explicitly identified this as an **open gap**: no adopted public dataset cleanly pairs JA3/JA3S/JA4 fingerprints with session-level packet-size/timing sequences, and self-generation of the malicious-TLS side was flagged as "a team task" that has never subsequently been designed or resolved in any later task. This detector's supervised classifier has no confirmed training-data source as of this review.
- **DGA traffic generation step:** **PARTIAL.** DGArchive supplies domain *strings*, but the dataset-evaluation task itself flagged that turning those strings into actual queried DNS traffic against the lab's internal resolver is "a team-built step," and this step has not been designed in any subsequent task (lab architecture describes the internal fake-DNS-resolver target, but not the query-generation script/process itself). Not a missing data *source*, but a missing *pipeline step* between the source and usable lab traffic.

### 2. Every feature can actually be derived from available data
**PASS, conditional on PCAP-level capture.** The data-model task's Field Availability matrix (§4 of that document) established that packet-size/timing sequences and JA3/JA3S/JA4 fingerprints are **PCAP-only** — not derivable from NetFlow/IPFIX/sFlow. The lab-architecture task confirms the monitoring host captures raw PCAP (`tcpdump`/`dumpcap`), so this condition is satisfied for the lab environment. This is flagged as a **conditional pass**, not unconditional, because it means the encrypted-malware and full-fidelity C2/DGA/tunnelling feature sets are contingent on PCAP capture being available at any future non-lab deployment point — a dependency worth stating plainly rather than assuming away.

### 3. No feature violates passive-only/no-decryption constraints
**PASS.** Reviewed the full feature list from the feature-engineering task against the official constraints: no feature requires payload decryption (JA3/JA3S/JA4 are handshake-metadata fingerprints, not decrypted content); no feature requires active probing (all rate/fan-out/entropy features are computed from passively observed packets); no feature assumes a return path or live query to the source. No violation found.

### 4. All online features are causal
**PASS, with one noted process gap.** The feature-engineering task's causality rule (§9.1) and the model-development methodology's leakage-prevention section (§4) both correctly identify that static reference tables (DGA n-gram model, known-JA3 list) are the one place causality could be silently violated, and both documents state the same discipline: build these only from pre-evaluation-period data. **However, no task has yet defined an actual verification/audit mechanism** that checks this discipline was followed at build time (e.g., a timestamp check on the reference-table build process) — this is currently a stated policy, not an enforced one. Flagged as a residual process gap, not a design flaw.

### 5. No train/test or temporal leakage remains
**PASS.** The model-development methodology's experiment-level splitting, temporal walk-forward preference, scenario-separation holdouts, and explicit leakage-prevention section together form a coherent, non-contradictory design. Supplementary public datasets are consistently treated as held-out-only across both the dataset-evaluation and model-development tasks — no contradiction found between the two.

### 6. Rule baselines exist where appropriate
**PASS.** All seven threats received a defined rule-based baseline in the rule-baseline task, and the ML-architecture task correctly builds on that evidence — using rules as the primary detector for DDoS/reconnaissance and as a first-pass/corroborating layer elsewhere. No threat is missing a rule component.

### 7. ML is only being used where justified
**PASS.** Every ML candidate in the model-selection task is explicitly justified by reference to the rule-baseline task's own findings (e.g., temporal models proposed only for C2 and encrypted-malware, where the threat-decomposition task originally identified the signal as sequence-shaped; no temporal model proposed for reconnaissance, where the rule-baseline task found rules already sufficient). No unjustified ML use found.

### 8. Model outputs can support confidence and evidence
**PASS for MVP models; unresolved for one optional-advanced component.** The calibration methodology (Platt/isotonic scaling) satisfies the confidence-score requirement for every MVP classifier, and feature-importance-based evidence extraction is available for every MVP model (all tree-based or linear). **The one unresolved item:** the model-selection task itself noted that the optional-advanced Isolation Forest for exfiltration "doesn't map as cleanly onto the alert schema's expected evidence, needing a translation step" — that translation step has never been designed. This does not block the MVP path (which uses Random Forest/XGBoost with normal feature-importance evidence), but it is an open item if the optional-advanced anomaly layer is ever adopted.

### 9. Selected models are feasible for near-real-time inference
**PASS for MVP; explicitly deferred for optional-advanced.** Every MVP model recommended is a lightweight classical model (Logistic Regression, Random Forest, XGBoost/LightGBM) with low expected inference latency. The optional-advanced temporal models (GRU, Temporal CNN, character-level CNN) are consistently flagged throughout the model-selection task as higher-latency and positioned as stretch goals, not MVP requirements — consistent, no contradiction. Actual latency numbers against a concrete throughput target cannot be confirmed yet since the throughput/latency target itself is only defined at the runtime-design stage, which has not yet occurred — noted as a forward dependency, not a current inconsistency.

### 10. Class imbalance and false-positive risks are addressed
**PASS.** Addressed consistently across three tasks: the feature-engineering task's completeness/quality flags, the model-selection task's per-model balancing method column, and the model-development methodology's dedicated class-imbalance and asymmetric threshold-tuning sections (low-FPR bias for DDoS/recon, recall bias for C2/encrypted-malware). No contradictions found between these three treatments.

### 11. Training and inference schemas match
**PARTIAL — a real gap identified.** Feature **names and definitions** are consistent end-to-end: the feature-engineering task's final inference feature schema (§10 of that document) uses the exact same field names the model-selection task lists as each candidate's input, and the model-development methodology tracks a "feature-schema version" per experiment run, implying schema alignment is treated as important. **However:** the lab-architecture task specifies that training data is produced via an **offline, batch flow-extraction tool** (nfstream/CICFlowMeter-style) reading from archived PCAP, while the feature-engineering task's online computation methods are built around **custom streaming primitives** (HyperLogLog, Count-Min Sketch, Welford accumulators, decay-based state). **No task has established that these two computation paths produce numerically equivalent feature values for the same underlying traffic.** This is the classic train/serve skew risk: matching field *names* does not guarantee matching field *values* if training-time features come from one implementation and inference-time features come from another. This has not been designed or reconciled anywhere in the approved work and is treated as a genuine open gap, not a formality.

---

## Traceability Table: THREAT → DATA → FEATURE → BASELINE → ML DETECTOR → OUTPUT

| THREAT | DATA | FEATURE | BASELINE | ML DETECTOR | OUTPUT |
|---|---|---|---|---|---|
| DDoS | hping3 (primary) + CIC-DDoS2019 attack-side (supplementary) + Slowloris (edge case) | `dst_packet_rate`, `dst_byte_rate`, `syn_no_completion_ratio`, `src_ip_entropy_toward_dst`, `unique_src_count_toward_dst` | Rate/SYN-ratio/entropy threshold rule (primary detector) | Random Forest (corroboration, MVP) | Alert: `threat_class=ddos`, confidence from rule-stage + corroboration score, evidence = triggering feature values |
| C2 Beaconing | Sandboxed C2 emulator (primary) + CTU-13 (validation) | `interarrival_mean/variance_pair`, `periodicity_score_pair`, `destination_repeat_count_pair`, `flow_size_consistency_pair`, `unique_destination_count_src` | Periodicity/repeat-count/consistency threshold rule | Random Forest/XGBoost on engineered features (MVP); GRU on raw sequence (optional advanced) | Alert: `threat_class=c2_beaconing`, calibrated confidence, evidence = periodicity/repeat statistics |
| DGA Domains | DGArchive/published algorithms — **traffic-generation pipeline step not yet designed** | `domain_char_entropy`, `domain_ngram_score`, `domain_length`, `nxdomain_ratio_host`, `query_rate_host`, `unique_domain_count_host` | Entropy/n-gram/NXDOMAIN-ratio threshold rule | Random Forest/XGBoost on lexical+behavioral features (MVP); char-CNN (optional advanced) | Alert: `threat_class=dga_domains`, calibrated confidence, evidence = flagged domain samples + host NXDOMAIN ratio |
| DNS Tunnelling | dnscat2 + iodine (primary) + CIRA-CIC-DoHBrw-2020 (DoH edge case, supplementary) | `query_length_avg/max_host`, `record_type_distribution_host`, `response_size_avg_domain`, `query_concentration_host_domain`, `doh_dot_flag` | Length/record-type/concentration threshold rule | Random Forest on engineered features (MVP) | Alert: `threat_class=dns_tunnelling`, calibrated confidence, evidence = query-length/record-type breakdown |
| Encrypted-Session Malware | **UNRESOLVED — no confirmed dataset or self-generation design exists** | `ja3_rarity_score`, `packet_size_prefix_mean/variance`, `interpacket_timing_prefix_mean/variance`, `sni_present_flag`, `session_duration_so_far` | Fingerprint blocklist + two-variance heuristic rule | Random Forest/XGBoost on summary features (MVP, **data-dependent**); Temporal CNN on raw sequence (optional advanced) | Alert: `threat_class=encrypted_malware`, confidence, evidence = fingerprint + size/timing statistics — **entire chain blocked upstream by the data gap** |
| Reconnaissance/Scanning | Self-generated scanning tool runs against lab targets | `unique_dst_port_count_src`, `unique_dst_host_count_src`, `scan_attempt_rate_src`, `flow_completion_ratio_src` | Fan-out/rate/completion-ratio threshold rule (primary detector) | Logistic Regression (corroboration, MVP) | Alert: `threat_class=reconnaissance`, confidence, evidence = fan-out counts and targeted ports/hosts |
| Data Exfiltration | Self-generated controlled asymmetric transfers | `outbound_inbound_byte_ratio_flow`, `cumulative_outbound_volume_host`, `destination_novelty_flag`, `outbound_baseline_deviation_host` | Ratio/volume/novelty threshold rule | Random Forest/XGBoost on engineered features (MVP); Isolation Forest (optional advanced, **evidence-mapping undesigned**) | Alert: `threat_class=data_exfiltration`, confidence, evidence = byte ratio/cumulative volume/deviation score |

---

## Inconsistencies and Missing Links — Consolidated

1. **[BLOCKING]** Encrypted-session malware has no resolved training-data source. This breaks the DATA→FEATURE→ML DETECTOR chain at its first link for one of the seven officially required threat categories.
2. **[BLOCKING]** No design exists reconciling the offline batch flow-extraction tool (training-data feature computation) with the online streaming primitives (inference-time feature computation) — a real train/serve skew risk affecting *every* detector's feature pipeline, not just one threat.
3. **[NON-BLOCKING, should close before implementation]** The DGA domain-list-to-traffic-generation step (querying DGArchive strings against the lab's internal resolver) has never been concretely designed, only named as a future team task.
4. **[NON-BLOCKING, minor]** No enforcement/audit mechanism exists to verify the causal-reference-table discipline (n-gram model, JA3 blocklist built only from pre-evaluation data) is actually followed, as opposed to just documented as a rule.
5. **[NON-BLOCKING, minor, optional-path only]** Isolation Forest's anomaly-score-to-alert-evidence translation for exfiltration has been identified but not designed — irrelevant to the MVP path, relevant only if that optional-advanced component is later adopted.

---

## DATA/ML STATUS: **NOT READY**

Two blocking items (#1 and #2 above) mean the system cannot be declared ready as a whole: one officially required threat category (encrypted-session malware) has no confirmed path from data to detector, and a foundational assumption underlying every other detector's train/inference consistency has never been verified. Declaring readiness without closing these would mean freezing a baseline on top of an unverified foundation.

**To reach READY, the following must be resolved first (not designed here — flagged for the next task):**
- A concrete, resolved data source or self-generation design for encrypted-session malware training data (closing gap #1).
- A decision and design for how training-time (batch) and inference-time (streaming) feature computation will be kept consistent — e.g., sharing a single feature-computation library/implementation across both paths, or a validated equivalence-testing process (closing gap #2).
- At minimum, an explicit design for the DGA traffic-generation pipeline step (closing gap #3), since this affects one of the seven required threats' actual buildability, not just a nice-to-have.

Gaps #4 and #5 are minor and do not block a READY determination once #1–#3 are closed, but should be tracked and closed before final submission polish.

No frozen DATA/ML DECISION BASELINE is produced, per the task's instruction that this is only appropriate upon a READY status.

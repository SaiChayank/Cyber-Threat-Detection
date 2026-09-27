# PS26145 — Source of Truth (Requirements & Scope Only)
**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic — NTRO**

Sources consulted:
- **[SIH]** Official SIH website listing (authoritative)
- **[PS-DOC]** `PS26145.docx` (supporting/derived document — contains explicit "Assumption" flags)
- **[CYBER-DOC]** `Cyber_Threats_-Unidirectional_IP_Traffic.docx` (supporting/derived document, restructured bullet form)

No architecture, dataset design, or ML modeling decisions are made here — requirements and scope only.

---

## 1. Official Objective

**OFFICIAL SIH:** Design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic (simulated) and detects, classifies, and scores cyber-security threats in near real time, using only passively collected data — under the constraint that the system can never re-contact the source/destination, complete a handshake, or push any action back across the ingest path. Output is intelligence: labelled alerts, confidence scores, and supporting evidence, shown on a visualization dashboard.

---

## 2. Target Users

| Item | Classification |
|---|---|
| SOC (Security Operations Centre) analysts monitoring dashboards / responding to alerts | **DERIVED REQUIREMENT** (stated in PS-DOC §2, not in official SIH text) |
| Threat intelligence teams doing historical/forensic analysis | **DERIVED REQUIREMENT** (PS-DOC §2) |
| Organizations running unidirectional monitoring infra generally (energy grids, defense, telecom, finance) | **DERIVED REQUIREMENT** (PS-DOC §2 — official SIH text only names NTRO as org, not the wider user base) |

**Note:** Official SIH text does not explicitly name "target users" — it only implies an operator/analyst via "visualisation dashboard" as the output surface. The specific user personas above are supporting-document elaboration, not verbatim SIH text.

---

## 3. Functional Requirements

| Requirement | Classification |
|---|---|
| Ingest one-directional/simulated IP traffic stream | **OFFICIAL SIH** |
| Detect, classify, and score threats | **OFFICIAL SIH** |
| Produce labelled alerts with confidence scores and supporting evidence | **OFFICIAL SIH** |
| Display results on a visualization dashboard | **OFFICIAL SIH** |
| Dashboard shows live and/or replayed detections with severity and confidence | **OFFICIAL SIH** |
| Alert click-through / drill-down to per-alert evidence detail | **DERIVED REQUIREMENT** (PS-DOC §10 "End-to-End User Experience") |
| Filter alerts by threat class or time window | **DERIVED REQUIREMENT** (PS-DOC §10) |
| Deliver as a working prototype = source repository | **OFFICIAL SIH** |
| Accompanying documentation: model(s) used, features engineered, training/validation approach | **OFFICIAL SIH** |

---

## 4. Non-Functional Requirements

| Requirement | Classification |
|---|---|
| Near real-time detection | **OFFICIAL SIH** |
| Streaming/incremental processing, not batch/end-of-run only | **OFFICIAL SIH** |
| Bounded alert latency | **OFFICIAL SIH** |
| Defined and demonstrated throughput target (flows/sec or Mbps) | **OFFICIAL SIH** |
| Macro F1-score > 0.85 | **ASSUMPTION** (PS-DOC §13, presented as an "Expected Result," not an SIH-mandated pass bar) |
| False Positive Rate < 5% for DDoS/Recon | **ASSUMPTION** (PS-DOC §13) |
| Alert latency "tens of milliseconds" | **ASSUMPTION** (PS-DOC §13 — SIH only says "bounded latency," no explicit number) |
| Handle severe class imbalance (benign ≫ attack) | **DERIVED REQUIREMENT** (PS-DOC §1/§6 calls this "near-certain" and mandates mitigation, but it's a data-quality inference, not literal SIH text) |

---

## 5. Architectural Constraints

All five below are **OFFICIAL SIH** (explicit in the SIH listing text, not just supporting docs):

1. **Read-only ingest** — no return path, no live query to source, no inline block; anything assuming these is out of scope.
2. **No payload decryption** — TLS/QUIC analyzed via metadata only.
3. **Streaming, not batch** — incremental processing, bounded-latency alerts.
4. **Defined throughput target** — must state and demonstrate tested traffic rate.
5. **Standardized alert schema** — structured record with (at minimum) timestamp, flow identifier, threat class, confidence score, supporting evidence.

Additional constraint framing (no new constraint, just phrasing) found only in supporting docs:

| Item | Classification |
|---|---|
| "No physical or protocol-level path back into the production network" (architecture description/rationale) | **OFFICIAL SIH** (present in SIH background text) |
| Explicit list of what the detector "cannot do": send probes, complete handshakes, push mitigation commands | **OFFICIAL SIH** |
| Suggested exact alert-schema field names (`flow_id`, `threat_class`, `confidence_score`, `supporting_evidence`) | **TEAM DECISION** (SIH gives the concept/fields required; exact schema key-naming is implementation choice) |

---

## 6. Required Threat Categories

**OFFICIAL SIH** — all six, explicitly named with detection basis given in the SIH text itself:

| # | Threat | Official detection basis (per SIH text) |
|---|---|---|
| a | Volumetric/protocol DDoS (SYN floods, UDP reflection/amplification, spoofed-source floods) | Flow-level rate + source-IP entropy statistics |
| b | Botnet C2 beaconing | Periodicity + inter-arrival analysis, regular intervals toward small destination set |
| c | DGA domains & DNS tunnelling | Entropy/n-gram analysis of DNS query names, query-length + record-type anomalies |
| d | Malware inside encrypted sessions | TLS/QUIC metadata only (JA3/JA3S/JA4 fingerprints, packet-size + timing sequences) — no decryption |
| e | Reconnaissance/port scanning | Fan-out patterns: single source → many destination ports/hosts |
| f | Data exfiltration | Asymmetric flow-volume anomalies, unusual outbound:inbound byte ratios |

Any additional/finer-grained sub-signatures (e.g., specific ML feature lists like JA3 hashing method, n-gram vector construction) beyond what's quoted above are **DERIVED REQUIREMENT** or **TEAM DECISION**, not official text.

---

## 7. Required Inputs

| Item | Classification |
|---|---|
| Passively observed data only: packet captures, exported flow records (NetFlow/IPFIX/sFlow), derived metadata | **OFFICIAL SIH** |
| One-directional stream of **simulated** IP traffic | **OFFICIAL SIH** |
| No real production/live traffic feed required | **OFFICIAL SIH** (implicit — "simulated" is explicit in SIH text) |

---

## 8. Required Outputs

| Item | Classification |
|---|---|
| Labelled alerts | **OFFICIAL SIH** |
| Confidence scores | **OFFICIAL SIH** |
| Supporting evidence per alert | **OFFICIAL SIH** |
| Visualization dashboard (live/replayed, severity + confidence shown) | **OFFICIAL SIH** |
| Structured/standardized alert record schema | **OFFICIAL SIH** (fields required: timestamp, flow ID, threat class, confidence score, supporting evidence — this exact field list is OFFICIAL SIH, quoted directly in the SIH listing) |
| Exportable reports (PDF/CSV) for shift handover/compliance | **OPTIONAL** (PS-DOC §15 "User-Facing Features") |

---

## 9. Official Dataset / Traffic-Generation Guidance

**OFFICIAL SIH** (Dataset Link field, verbatim guidance):
- Synthetic and lab-generated traffic only — **no real-world dataset URL provided**.
- Benign traffic generation tools: iperf3, Ostinato, TRex.
- Attack traffic generation tools: hping3 (SYN/UDP floods), Slowloris (slow HTTP exhaustion), dnscat2/iodine (DNS tunnelling).
- DGA samples: published algorithms (e.g. via DGArchive) or a sandboxed C2 emulator for beaconing timing realism.
- Feature extraction guidance text is **truncated mid-sentence** in the official SIH field ("Feature extraction: Extract flow") — SIH provides no further detail here.

| Item | Classification |
|---|---|
| No dataset URL/download exists — team must generate its own traffic | **OFFICIAL SIH** (confirmed, not an inference) |
| Specific row counts, column schemas, time period | **ASSUMPTION** (PS-DOC §5 explicitly flags these with "⚠ Assumption" — SIH provides none of this) |
| Specific feature list (flow rate stats, entropy, JA3/JA3S/JA4, n-grams, fan-out metrics, etc.) | **DERIVED REQUIREMENT** — reasonable elaboration tied directly to the six official threat categories, but not literal SIH text beyond the per-threat "detection basis" phrases in Section 6 |

---

## 10. Missing Technical Decisions

Not specified anywhere in official SIH text or supporting docs — will need team decisions later (no design happening now, just flagging the gaps):

- Exact model architecture/algorithm choice (Random Forest vs. XGBoost vs. LSTM/Transformer vs. ensemble)
- Exact feature schema/column definitions and window sizes for streaming aggregation
- Streaming/message-queue technology choice (Kafka vs. ZeroMQ vs. something simpler for hackathon scope)
- Storage technology for alerts/time-series data
- Dashboard framework and hosting approach
- Concrete throughput target number to test against (SIH requires *a* stated target, not a specific value)
- Concrete latency target number (SIH requires "bounded latency," not a specific ms figure)
- Train/test split strategy, evaluation metric thresholds for internal go/no-go
- Authentication/access control for the dashboard (explicitly out of scope per PS-DOC §14, but a gap nonetheless)
- Exact synthetic dataset volume/duration/topology to generate

---

## 11. Assumptions Made in Supporting Documents

Explicitly flagged as assumptions inside PS-DOC (⚠ marked in the source) or reasonably inferred by CYBER-DOC/PS-DOC beyond official text:

- Row count "likely hundreds of thousands to millions of flow records" — **ASSUMPTION**
- Column schema (5-tuple, byte/packet counts, duration, inter-arrival times, flags, entropy, JA3, etc.) — **ASSUMPTION**
- No fixed historical time period; traffic generated on-demand — **ASSUMPTION**
- Expected performance bar (Macro F1 > 0.85, FPR < 5%, latency "tens of ms") — **ASSUMPTION**
- Real-world generalization from simulated traffic is assumed sufficient — **ASSUMPTION** (PS-DOC §14, explicitly flagged)
- Feature extraction assumed to complete within latency budget before inference — **ASSUMPTION** (PS-DOC §14, explicitly flagged)

---

## 12. Conflicts Between Documents

No direct contradictions found between PS-DOC and CYBER-DOC — CYBER-DOC is essentially a bulletized restatement of the same official content with less elaboration and no "Expected Results"/dataset-assumption sections. Differences are of **coverage/detail**, not conflicting facts:

| Topic | PS-DOC | CYBER-DOC | Official SIH | Resolution |
|---|---|---|---|---|
| Performance targets (F1, FPR, latency numbers) | States specific numeric targets | Not mentioned at all | Not mentioned | Treat PS-DOC numbers as **ASSUMPTION**/aspirational, not a hard SIH requirement |
| Target user personas | Detailed (SOC analyst, threat intel team, etc.) | Not mentioned | Not mentioned | Treat as **DERIVED REQUIREMENT**, non-binding elaboration |
| Tech stack suggestions | Full stack table given | Not mentioned | Not mentioned | **TEAM DECISION** territory, not SIH-mandated |
| Dataset column/row specifics | Explicitly flagged as unknown assumptions | Not addressed | Not specified | Consistent — both treat this as unknown |

**Conclusion:** No factual conflict exists between the two supporting documents or with the official listing. PS-DOC is simply more elaborated/interpretive; CYBER-DOC stays closer to a literal restructuring of the SIH text.

---

## 13. Optional Enhancements

(from PS-DOC §15 "Additional Features" — none of these are required for a valid submission)

- Anomaly detection layer (Isolation Forest/Autoencoder) for unknown/zero-day threats
- Per-threat confidence calibration (Platt scaling/isotonic regression)
- Online/incremental learning from analyst feedback
- Threat correlation engine (grouping related alerts into one incident)
- Alert triage queue with analyst True/False Positive feedback
- Threat timeline view across multi-stage attacks
- Export/reporting (PDF/CSV)
- Traffic heatmap by source-IP range/time
- SHAP-based feature-importance drill-down per alert
- Historical trend dashboard
- Automated composite severity scoring

---

## 14. Future / Production Features

(explicitly framed in supporting docs as beyond-prototype/production concerns, not hackathon-scope)

- Pipeline integrity monitoring (hash-verify model/code at startup)
- Tamper-proof/append-only alert logging with cryptographic chaining
- Horizontal scaling of feature extraction workers
- Pluggable threat-module architecture for adding new threat types
- Docker Compose/Kubernetes full orchestration packaging
- Automated throughput benchmarking suite
- Authentication, RBAC, audit logging for the dashboard (explicitly noted as **not** specified/needed now — PS-DOC §14)
- Security accreditation of the software stack for real NTRO deployment

---

## Consolidated Requirement Matrix

| # | Item | Classification |
|---|---|---|
| 1 | Core objective (ingest → detect/classify/score → alert → dashboard) | OFFICIAL SIH |
| 2 | Named user personas (SOC analyst, threat intel team) | DERIVED REQUIREMENT |
| 3 | Wider org beneficiaries (energy/defense/telecom/finance) | DERIVED REQUIREMENT |
| 4 | Dashboard drill-down / filter by class-time | DERIVED REQUIREMENT |
| 5 | Prototype as source repo + documentation | OFFICIAL SIH |
| 6 | Near-real-time, streaming, bounded latency, defined throughput | OFFICIAL SIH |
| 7 | Numeric performance targets (F1>0.85, FPR<5%, ms latency) | ASSUMPTION |
| 8 | Class-imbalance handling requirement | DERIVED REQUIREMENT |
| 9 | Read-only ingest / no return path / no probing / no handshake / no mitigation push | OFFICIAL SIH |
| 10 | No TLS/QUIC payload decryption | OFFICIAL SIH |
| 11 | Standardized alert schema (timestamp, flow ID, threat class, confidence, evidence) | OFFICIAL SIH |
| 12 | Exact schema key-naming conventions | TEAM DECISION |
| 13 | Six required threat categories + stated detection basis | OFFICIAL SIH |
| 14 | Detailed feature engineering list (JA3 hashing, n-gram vectors, fan-out metrics, etc.) | DERIVED REQUIREMENT |
| 15 | Passive input types (pcap, NetFlow/IPFIX/sFlow, metadata), simulated traffic | OFFICIAL SIH |
| 16 | No real dataset exists; must self-generate | OFFICIAL SIH |
| 17 | Traffic-generation tool list (iperf3, hping3, Slowloris, dnscat2/iodine, DGArchive) | OFFICIAL SIH |
| 18 | Dataset row count / column schema / time period specifics | ASSUMPTION |
| 19 | Model architecture choice | TEAM DECISION (missing — to be made) |
| 20 | Streaming tech, storage tech, dashboard framework choice | TEAM DECISION (missing — to be made) |
| 21 | Concrete throughput/latency numeric targets to test against | TEAM DECISION (missing — SIH requires *a* target, not a number) |
| 22 | Exportable reports (PDF/CSV) | OPTIONAL |
| 23 | Anomaly detection, calibration, online learning, correlation engine, triage feedback, heatmaps, SHAP drill-down, trend dashboard, severity scoring | OPTIONAL |
| 24 | Pipeline integrity hashing, tamper-proof logging, horizontal scaling, pluggable modules, full container orchestration, benchmarking suite, auth/RBAC/audit logging, accreditation | FUTURE |

---

**No architecture, dataset schema, or ML modeling decisions have been made in this document.** This is scope/requirements analysis only, ready to serve as the reference baseline for subsequent design tasks.

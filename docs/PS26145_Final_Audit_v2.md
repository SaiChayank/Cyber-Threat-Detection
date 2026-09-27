# PS26145 — Final Pre-Blueprint Audit (Second Pass)
**Scope:** Audit only. This re-runs the full audit now that Testing (Verification Strategy), Deployment (Implementation & Deployment Structure), MVP Prioritization (Capability Classification), and SIH Demo Strategy all exist as actual frozen documents — closing the gap the first audit flagged (they didn't exist yet). No new features are added here; where a contradiction has one clear, already-implied correct answer, this audit rules on it rather than leaving it open, since that is exactly what a *final* pre-blueprint audit is for.

---

## Six-Perspective Summary

1. **SIH requirement compliance:** Strong, with one disclosed, deliberate exception — encrypted-session malware will be demoed via its rule-based detector only, with the ML classifier explicitly documented as future work (per the capability-classification and demo-strategy decisions). This is a known, honest trade-off, not a silent gap, and is treated below as HIGH rather than BLOCKER on that basis.
2. **Technical correctness:** The train/serve feature-computation skew flagged in the first audit is now resolved **by design**, not just by intent — the implementation/deployment task's repository structure makes ML training reuse the same `replay → ingest → streaming → features` code path as live inference, eliminating the two-implementation risk structurally. One loose end remains: an earlier document (lab architecture) still describes a separate offline batch flow-extraction tool for this same purpose. This audit rules on that contradiction below (§A).
3. **End-to-end integration:** Consistent almost everywhere now. Two small, previously-flagged integration seams remain open (the Threat Analytics endpoint extension; the security-review schema additions not yet folded into the persistence layer) — both concrete, scoped, non-blocking.
4. **ML scientific validity:** No longer conditional on an unresolved skew risk, once §A's ruling is applied. The methodology's leakage prevention, causal features, and calibration approach stand as designed.
5. **Hackathon feasibility:** Substantially improved since the first audit — the multi-VM lab was replaced with single-host Docker Compose, custom sketch structures were replaced with existing libraries, and the capability-classification task explicitly trimmed scope (six-threat MVP, no deep sequence models, no anomaly detection, no correlation). This is now a consciously right-sized plan, not an unaddressed risk.
6. **Demonstrability:** Fully addressed — every step has a script, an expected outcome, and a validated fallback. The one deliberate compliance gap (encrypted-malware) has a rehearsed, honest line rather than being left to chance.

---

## A. Unresolved Contradictions

| # | Finding | Ruling | Severity |
|---|---|---|---|
| A1 | The lab-architecture document describes training-data feature extraction via a separate **offline batch tool** (nfstream/CICFlowMeter-style); the implementation-deployment document's repository design has `ml/` reuse the **same streaming feature-computation modules** used at live inference (`replay → ingest → streaming → features`) — a direct contradiction between two frozen documents on how a core mechanism works. | **Ruled:** the implementation-deployment design is authoritative on this point, since it was an explicit, justified structural fix to the train/serve skew risk (Correction 2 from the first audit). The lab-architecture document's batch-tool description is **superseded** for the purpose of generating features that feed model training; such tools may still be used only for ad hoc manual inspection of captured traffic, never for producing training features. This ruling is carried into the Decision Register below so the Master Blueprint has one answer, not two. | MEDIUM (resolved by ruling; a documentation update to the lab-architecture file is the only remaining action, not a new engineering decision) |
| A2 | The model-development methodology's team targets (Macro F1 ≥ 0.70 MVP) remain distinct from PS-DOC's own assumption-flagged targets (F1 > 0.85) — restated once more, unchanged from the first audit, since this is intentional and already well-documented. | No new ruling needed. | LOW |

## B. Missing Components

| # | Finding | Severity |
|---|---|---|
| B1 | Security-review MVP schema additions (model-artifact hash field on `model_versions`, dataset-artifact hash field on the experiment manifest, specific `audit_events` event types) were specified as prose intent but still have not been folded into the actual persistence-layer entity definitions. | MEDIUM |
| B2 | The DGA domain-list-to-actual-DNS-traffic generation script remains named but not concretely designed — the demo strategy already anticipates this with a fallback, but the underlying gap itself is unchanged from the first audit. | HIGH |
| B3 | No documented capacity estimate ties the committed throughput target (≥2,000 flows/sec) to the chosen `asyncio` + Redis Streams stack — the number was set as a team goal, not derived from an engineering estimate of what that specific stack can plausibly sustain. | MEDIUM |

*(All other Missing Components from the first audit — testing strategy, deployment/runbook, consolidated MVP prioritization, SIH demo strategy — are now resolved by the four documents this audit reviews, and are not repeated here.)*

## C. Unnecessary Complexity

No new findings. The first audit's three complexity findings (multi-VM lab, hand-rolled sketch structures, seven fully-tuned/calibrated detectors) have all been explicitly resolved as adopted decisions in the implementation-deployment and capability-classification tasks — Docker Compose replaces the multi-VM lab, existing libraries replace hand-rolled sketches, and calibration effort is explicitly tiered by data maturity per detector. **Closed.**

## D. High-Risk Dependencies

| # | Finding | Severity |
|---|---|---|
| D1 | The DGA detector's live-demo readiness depends entirely on B2 (the traffic-generation script) being completed before demo day; the demo strategy's fallback (replay-only) covers the demo itself but does not remove the underlying schedule risk to actually having a working DGA detector at all. | HIGH |
| D2 | PCAP-level capture at the mirror point remains a hard dependency for encrypted-malware (rule-only), full C2, and full DGA/tunnelling feature fidelity, with no designed fallback if the Docker capture container ever needs to fall back to flow-only export. Unchanged from the first audit. | MEDIUM |

*(The first audit's D1 — train/serve equivalence — is resolved by the ruling in §A1 and is not repeated here.)*

## E. Missing Tests

| # | Finding | Severity |
|---|---|---|
| E1 | No test guards against **future code drift** reintroducing a second feature-computation implementation now that the structural fix (§A1) relies on `ml/` continuing to import from `streaming/`/`features/` rather than a shortcut reimplementation — a cheap regression test (asserting the training pipeline's feature-computation call sites resolve to the same modules as the runtime pipeline's) would close this permanently. | MEDIUM |
| E2 | Execution of the already-designed passive-ingest no-egress test and the load/throughput benchmark has not yet occurred — expected and appropriate at this design stage, listed here only as still-outstanding work, not a design flaw. | LOW |

*(The first audit's E1 — literal train/serve equivalence test — and E2 — end-to-end integration test plan — are both resolved: the former by §A1's structural fix, the latter by the verification strategy's integration section.)*

## F. Missing Demo Capabilities

| # | Finding | Severity |
|---|---|---|
| F1 | The Threat Analytics page's aggregate visualizations still depend on an `/api/analytics/summary` extension that has been named but not concretely designed — unchanged from the first audit, now the only remaining item in this category. | MEDIUM |

*(The first audit's F1 — encrypted-malware demoability — and F2 — no rehearsed demo script — are both resolved by the demo-strategy task.)*

## G. Requirements Without Traceability

| # | Finding | Severity |
|---|---|---|
| G1 | The official "AI-based detection" framing applies, strictly, to all seven detection problems; encrypted-session malware's current implementation path traces only to a rule-based detector, not an AI/ML one, for the MVP. This is disclosed and deliberate (per the capability-classification decision), but it is worth stating explicitly here as a compliance nuance the submission documentation must own plainly, not one this audit should quietly wave through as fully compliant. | HIGH |

*(The first audit's G1 — no committed throughput number — is resolved by the verification strategy; G2 — RBAC/tamper-evident target — is substantially resolved, since a concrete decision now exists for the lightweight tamper-evident version; only RBAC's status is unchanged, kept at LOW.)*

## H. Features That Should Be Removed From MVP

No new findings. The first audit's four findings (full calibration for weak-data detectors, multi-VM lab, deep sequence models, Isolation Forest) are all resolved as adopted decisions in the capability-classification and implementation-deployment tasks. **Closed.**

---

## MASTER BLUEPRINT READINESS: **READY**

No BLOCKER-level issue remains. The two BLOCKERs from the first audit are both resolved: encrypted-session malware's data gap is resolved by an explicit, documented descoping decision (not a silent gap), and the train/serve feature-computation skew is resolved by a structural design fix, now formally ratified by this audit's ruling in §A1. The remaining HIGH-severity items (B2/D1's DGA script, G1's AI-vs-rule compliance nuance) are real, scoped, and already carry documented fallbacks — they are scheduling and documentation risks to manage during build, not open design questions blocking blueprint generation.

---

## FINAL APPROVED DECISION REGISTER
*(for use by the Master Blueprint prompt — every entry below is settled; nothing here is a discussion point)*

**Scope**
- Seven official threat categories addressed; six with full rule+ML hybrid detection, one (encrypted-session malware) with rule-based detection only for this prototype, ML classifier explicitly documented as future work pending a resolved training-data source.
- Rule-primary detectors: DDoS, Reconnaissance. Classifier-primary detectors: C2 Beaconing, DGA Domains, DNS Tunnelling, Data Exfiltration. Rule-only (MVP): Encrypted-Session Malware.

**Data & ML**
- Lab traffic generated via the official SIH-named tools (iperf3/Ostinato/TRex benign; hping3/Slowloris/dnscat2/iodine/DGArchive/sandboxed-C2-emulator attack), supplemented only by CIC-DDoS2019 (attack-side), CTU-13, and CIRA-CIC-DoHBrw-2020 as held-out validation, never blended into training.
- Canonical schema: `FlowRecord`/`DNSRecord`/`TLSQUICMetadata`, causal streaming features computed via existing sketch libraries (not hand-rolled), MVP models are classical (Logistic Regression/Random Forest/XGBoost), calibrated via Platt/isotonic scaling, tiered by detector data-maturity.
- **Ruling (supersedes the lab-architecture document on this point):** training-data feature computation reuses the same `replay → ingest → streaming → features` modules used at live inference. No separate offline batch flow-extraction tool is used to produce training features.
- Deep sequence models, Isolation Forest, and full anomaly detection are explicitly out of MVP scope, documented as future work.

**System Architecture**
- Runtime pipeline: Python `asyncio` core, Redis Streams as the sole external message-bus component.
- Backend: single FastAPI service (modular monolith, no microservices), SSE for live alerts, SQLite (prototype) upgrading to PostgreSQL (production).
- Deployment: single-host Docker Compose for the hackathon build (supersedes the original multi-VM lab topology, which remains valid only as production-representative documentation).
- Alert schema: official fields (timestamp, flow ID, threat class, confidence, evidence) plus derived-required fields (severity, detector type, model version, explanation) and optional fields (correlation ID, reserved for future use).

**Testing**
- Full verification strategy in place: unit/ML/integration/system/security/architectural-compliance/performance suites, with committed MVP performance targets of at least 2,000 flows/sec and p95 end-to-end alert latency under 2 seconds.

**Demo**
- 15-step live sequence with a validated replay fallback for every live-triggered step; encrypted-malware step scripted with an explicit, confident disclosure of its rule-only status.

**Open, non-blocking follow-ups to schedule during build (not design questions):**
- Close the DGA traffic-generation script (B2/D1).
- Design the `/api/analytics/summary` extension for Threat Analytics (F1).
- Fold the security-review's hash-field/audit-event schema additions into the persistence layer (B1).
- Add a regression test guarding against future reintroduction of a second feature-computation implementation (E1).
- Update the lab-architecture document to reflect the A1 ruling above (documentation sync only).

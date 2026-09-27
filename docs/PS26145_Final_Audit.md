# PS26145 — Final Pre-Blueprint Audit
**Scope:** Audit only — no new features, redesigns, or additions. This checks everything established across the project's design tasks against six perspectives and eight finding categories, then issues a readiness verdict.

**Note on the requested "frozen baselines":** Research, Data/ML, and System Architecture baselines exist as the documents already produced in this conversation (Source of Truth, threat/data/dataset analysis, lab architecture, data model, feature engineering, rule baseline, ML architecture/model selection, model-development methodology, runtime pipeline, alert schema, backend, SOC UI, security review). **Testing, Deployment, MVP Prioritization, and SIH Demo Strategy do not exist as dedicated frozen documents** — their content is either partially embedded in other documents (ML train/val/test methodology stands in for part of "Testing"; MVP/Alternative/Advanced picks are scattered across the model-selection and SOC-UI tasks in place of a consolidated "MVP Prioritization") or entirely absent ("Deployment" and "SIH Demo Strategy" have no corresponding document at all). This gap is itself a finding (§B) rather than something to paper over.

---

## Six-Perspective Summary

1. **SIH requirement compliance:** Mostly strong — read-only ingest, no-decryption, streaming/bounded-latency, alert-schema fields, and dashboard requirements all have confirmed implementation paths across the approved documents. **One official requirement does not**: encrypted-session malware (one of the six explicitly named threat categories) has no resolved training-data source, so its implementation path is currently broken, not just weak.
2. **Technical correctness:** The architecture is internally sound (causality discipline, leakage prevention, backpressure design, dedup logic), but the **readiness review's train/serve feature-computation skew finding was never closed** by any later task — it is carried forward unresolved into this audit.
3. **End-to-end integration:** Field names and identifiers (`flow_id`, `experiment_id`, `model_version`, alert schema fields) trace consistently from the lab through to the UI. Two integration seams are incomplete: the Threat Analytics page's assumed analytics-endpoint extension, and the security review's MVP-classified schema additions (model/dataset hash fields, audit event types) that were specified in prose but never folded back into the actual `model_versions`/manifest schemas.
4. **ML scientific validity:** The train/val/test methodology, leakage prevention, and calibration approach are all sound in design — but their validity is conditional on the unresolved train/serve skew issue (perspective 2); until that's closed, any metric number produced by this pipeline is provisional, not confirmed.
5. **Hackathon feasibility:** The largest feasibility risk is scope, not any single flaw — a multi-VM isolated lab, seven fully-tuned-and-calibrated ML detectors, and custom-built streaming sketch structures (HyperLogLog, Count-Min Sketch, Bloom filters) collectively represent more engineering than a typical hackathon timeline supports at the fidelity designed. None of this is wrong, but it is more than an MVP needs, and no scoped-down build plan exists yet.
6. **Demonstrability:** Encrypted-session malware cannot be demoed at all today (no data, no model). No rehearsed demo script or fallback plan exists for a live-capture judging session. These are separate risks from technical correctness — a system could be technically fine and still fail to demo well without this.

---

## A. Unresolved Contradictions

| # | Finding | Severity |
|---|---|---|
| A1 | The readiness review returned **NOT READY** with two explicit blockers; every subsequent task (runtime pipeline, alert schema, backend, UI, security review) proceeded to build on top of that unresolved foundation without re-flagging or closing it at each step. This is a process contradiction — later work implicitly treats the foundation as settled when it was explicitly marked otherwise. | MEDIUM |
| A2 | The model-development methodology's internal "team targets" (Macro F1 ≥ 0.70 MVP) are deliberately different from PS-DOC's own assumption-flagged targets (F1 > 0.85) — intentional and already documented, but worth restating once more here so the Master Blueprint doesn't cite the wrong number as "the" target. | LOW |

## B. Missing Components

| # | Finding | Severity |
|---|---|---|
| B1 | Encrypted-session malware has no resolved training-data source — flagged in the dataset-evaluation task, never subsequently closed. | **BLOCKER** |
| B2 | The DGA domain-list-to-actual-DNS-traffic generation step has never been concretely designed, only named as "a team task." | HIGH |
| B3 | No software/integration testing strategy exists for the pipeline and backend code itself, distinct from the ML train/val/test methodology (unit tests, pipeline-stage integration tests, API contract tests). | HIGH |
| B4 | No deployment/run-book document exists — no environment setup, dependency list, or run instructions for standing up the full stack. | HIGH |
| B5 | No consolidated MVP-prioritization register exists — correct decisions are scattered across the model-selection and SOC-UI tasks but never assembled into one authoritative "this is what ships" document. | MEDIUM |
| B6 | No SIH demo strategy/script exists — no defined presentation order, no chosen demo scenarios/experiment IDs, no fallback plan for a live-capture issue during judging. | HIGH |
| B7 | Security-review MVP items (model-artifact hash field, dataset-artifact hash field, specific audit-event types) were specified as prose intent but never folded back into the actual `model_versions` table or experiment-manifest schema they extend. | MEDIUM |

## C. Unnecessary Complexity

| # | Finding | Severity |
|---|---|---|
| C1 | The lab architecture's multi-VM topology (separate hosts for benign generation, attack simulation, victim, C2 endpoint, monitoring, and orchestration) is heavier than a hackathon timeline typically supports; the same isolation properties (no egress route, promiscuous/mirrored capture, no IP on the capture interface) are achievable with a single-host Docker Compose setup on an internal-only bridge network, at a fraction of the setup cost. | MEDIUM |
| C2 | The feature-engineering design's custom-built streaming primitives (HyperLogLog, Count-Min Sketch, Bloom filter, Welford accumulators) are conceptually correct but expensive to hand-implement correctly under time pressure; existing lightweight libraries (e.g., `datasketch`, `probables`) satisfy the same design without any structural change. | MEDIUM |
| C3 | Building and tuning all seven full ML detectors — plus calibration, plus threshold tuning, plus optional-advanced variants — to a polished standard is more ML engineering than a hackathon timeline typically supports well. | LOW |

## D. High-Risk Dependencies

| # | Finding | Severity |
|---|---|---|
| D1 | Every detector's reported evaluation metrics depend on training-time (offline batch flow-extraction) and inference-time (custom streaming primitives) feature computation producing equivalent values — never verified. This is the same root issue as the readiness review's gap #2, still open. | **BLOCKER** |
| D2 | The DGA and encrypted-malware detectors both depend on data-generation steps that don't yet exist (B1, B2); if either slips, two of seven required threat categories have nothing to demo. | HIGH |
| D3 | PCAP-level capture at the mirror point is a hard dependency for encrypted-malware, full C2, and full DGA/tunnelling feature fidelity (per the data-model task's field-availability matrix); if the lab's actual capture setup ever falls back to flow-only export, three detectors silently lose their primary signal with no designed fallback. | MEDIUM |

## E. Missing Tests

| # | Finding | Severity |
|---|---|---|
| E1 | No test verifies train/serve feature-computation equivalence (directly tied to D1) — the single most important missing test in the project. | HIGH |
| E2 | No end-to-end integration test plan exists covering the full chain from Passive Ingest through Alert Output to dashboard rendering. | MEDIUM |
| E3 | The security review specified a test method for the passive-ingest no-egress invariant (run capture in a network namespace with all egress blocked) but this test has not actually been run — expected at this design stage, listed here as outstanding, not as a flaw. | MEDIUM |
| E4 | No load/throughput benchmark has actually been executed against the recommended asyncio + Redis Streams stack to confirm it meets whatever concrete throughput number the team eventually commits to. | LOW |

## F. Missing Demo Capabilities

| # | Finding | Severity |
|---|---|---|
| F1 | Encrypted-session malware cannot be demoed at all today — no data, no trained model. Direct consequence of B1. | **BLOCKER** |
| F2 | No rehearsed/scripted demo flow exists (tied to B6) — a live judging session currently has no defined order or fallback plan. | HIGH |
| F3 | Threat Analytics' most differentiating visuals (confidence histograms, fan-out aggregates, DNS anomaly trend charts) depend on an `/api/analytics/summary` extension that was flagged in the SOC-UI task but never designed. | MEDIUM |

## G. Requirements Without Traceability

| # | Finding | Severity |
|---|---|---|
| G1 | "Demonstrated throughput target" (an official SIH requirement) has a design path (accelerated replay + throughput endpoint + Overview widget) but no committed concrete number in any frozen document — nothing to point to yet as "our demonstrated throughput of X." | MEDIUM |
| G2 | RBAC and tamper-evident logging were classified RECOMMENDED in the security review but have no target document describing what "the recommended version" concretely looks like if time allows building it. | LOW |

## H. Features That Should Be Removed From MVP

| # | Finding | Severity |
|---|---|---|
| H1 | Full production-grade calibration (Platt/isotonic) and threshold tuning for all seven detectors is more than a first demoable prototype needs — MVP should ship simpler fixed/staged confidence for the weakest-data detectors (DGA, encrypted-malware) while full calibration is built out only for the detectors with the most mature data (DDoS, reconnaissance, C2). | MEDIUM |
| H2 | The multi-VM lab topology (C1) should be excluded from the actual MVP build in favor of the single-host Docker Compose equivalent; it may remain documented as the "production-representative" architecture without being what's built for the hackathon. | MEDIUM |
| H3 | Optional-advanced temporal models (GRU, Temporal CNN, char-CNN) should be formally excluded from the MVP build — already implied by their "optional advanced" labeling, restated here as an explicit MVP-exclusion decision. | LOW |
| H4 | Isolation Forest for exfiltration (optional-advanced) should be excluded from MVP given its unresolved evidence-mapping design gap, noted separately from H3 since it has its own specific blocking sub-issue. | LOW |

---

## MASTER BLUEPRINT READINESS: **NOT READY**

Two BLOCKER-level issues remain open (B1/F1 and D1), consistent with the instruction not to declare readiness while any BLOCKER persists.

---

## Exact Corrections Required Before Generating the Blueprint

**Correction 1 — resolve B1/F1 (encrypted-session malware data gap).** Do one of the following, explicitly:
- (a) Confirm a concrete, executable data-acquisition plan for encrypted-session malware — either a specific public dataset not previously identified, or a fully specified self-generation design (exact TLS-emulation tool/method, exact malicious-fingerprint reproduction approach) — and record it in the dataset-evaluation baseline; **or**
- (b) Formally descope encrypted-session malware from the MVP submission, and propagate that decision into every affected document (the traceability table, the model-selection summary, the SOC-UI evidence examples, and the SIH-compliance mapping) so no downstream artifact silently assumes this detector exists.

**Correction 2 — resolve D1 (train/serve feature-computation equivalence).** Do one of the following, explicitly:
- (a) Run and record an equivalence test comparing the offline batch flow-extraction tool's output against the streaming feature-engineering module's output on the same captured traffic, confirming values match within a stated tolerance; **or**
- (b) Eliminate the two-implementation risk structurally by generating training data through the same streaming feature-computation module (via replay mode, already designed for this purpose) instead of the separate offline batch tool.

No other item in this audit blocks blueprint generation. HIGH-severity items (B2, B3, B4, B6, D2, E1, F2) are strongly advised to be addressed alongside or immediately after the two corrections above, but are not, by the BLOCKER/HIGH distinction applied throughout this audit, prerequisites to generating the blueprint itself.

# PS26145 — Capability Classification & Build Recommendation
**Scope:** Every capability decided across this project's design tasks, classified into five tiers, plus a detailed evaluation of twelve named advanced ideas, ending in an explicit build/no-build call for the first complete prototype.

**Tiers used throughout:**
1. **OFFICIAL SIH REQUIREMENT** — stated or directly implied by the SIH listing text itself.
2. **REQUIRED FOR WORKING MVP** — not named by SIH, but the system cannot function/be judged fairly without it.
3. **HIGH-VALUE HACKATHON DIFFERENTIATOR** — not required, but disproportionately strengthens the submission relative to its cost.
4. **OPTIONAL ADVANCED** — genuinely useful, but a fair trade-off exists to defer it.
5. **FUTURE/PRODUCTION** — real, but wrong scope for a hackathon prototype under any reasonable time budget.

---

## Part 1 — Classification of Everything Already Decided

| Capability | Tier | Note |
|---|---|---|
| DDoS detection (rule primary + RF corroboration) | 1 | Named threat category, explicit detection basis in the SIH text |
| Reconnaissance/scanning detection (rule primary + LogReg corroboration) | 1 | Same |
| C2 beaconing detection | 1 | Same |
| DGA domain detection | 1 | Same — **status: blocked on the DGA traffic-generation pipeline step (final-audit finding B2)**, otherwise ready |
| DNS tunnelling detection | 1 | Same |
| Encrypted-session malware detection | 1 | Same — **status: blocked, no training data (final-audit finding B1/F1)** |
| Data exfiltration detection | 1 | Same |
| Canonical data model (FlowRecord/DNSRecord/TLS metadata) | 2 | Foundational plumbing every detector depends on; not itself SIH-named |
| Causal streaming feature engineering | 2 | Required to satisfy the official streaming/bounded-latency constraint |
| Rule-based baseline (all seven threats) | 2 | Not SIH-mandated by name, but core to the chosen architecture and the primary detector for two threats |
| Runtime pipeline (asyncio + Redis Streams) | 2 | Required to satisfy streaming/throughput/latency requirements |
| Alert schema official fields (timestamp, flow ID, threat class, confidence, evidence) | 1 | Verbatim from the SIH listing |
| Dashboard with live/replayed detections, severity, confidence | 1 | Verbatim from the SIH listing's expected-solution text |
| Replay mode | 1 | Directly implied by "live **or replayed** detections" in the official text |
| Demonstrated throughput target | 1 | Explicit official constraint |
| Documentation of models/features/training approach | 1 | Explicit official deliverable |
| Backend API + database | 2 | Required to serve the official dashboard requirement — not itself named |
| Basic security (auth, input validation, CORS, secrets management) | 2 | Not SIH-named, but a system with none of this is not a credible working prototype |
| Model/dataset integrity hashing | 2 | Cheap, protects the credibility of every ML claim the submission makes |
| Docker-based single-host lab (vs. multi-VM) | 2 | Implementation simplification, not itself a requirement, but necessary for the environment to exist within hackathon time |
| Rule-vs-ML comparison narrative | 3 | Not required by SIH, not strictly needed for a "working" system, but a genuinely strong, cheap differentiator (see Part 3) |
| RBAC (multi-role) | 4 | Only one functional role exists anywhere in the design; nothing to differentiate yet |
| Rate limiting | 4 | Low risk on a closed demo network |
| Container hardening (beyond basic hygiene) | 5 | Real production concern, not judged in a hackathon demo |
| Full API abuse protection | 5 | Same reasoning |

---

## Part 2 — Named Advanced Ideas: Detailed Evaluation

### Anomaly Detection (Isolation Forest for exfiltration)
- **VALUE:** Medium — catches evasive exfiltration patterns beyond what labeled lab data covers, but the supervised MVP path already demoes exfiltration convincingly.
- **EFFORT:** Medium — training plus threshold tuning, plus an unresolved evidence-mapping design gap (already flagged in the model-selection task).
- **RISK:** Medium-high — weak explainability; the anomaly-to-evidence translation was never designed.
- **DEPENDENCIES:** The supervised exfiltration model already working; a defined "normal" baseline.
- **DEMO IMPACT:** Low-medium — hard to demonstrate convincingly without staging a genuinely novel, unlabeled attack pattern live.
- **Tier: 4 (OPTIONAL ADVANCED).**

### Calibrated Confidence (Platt/isotonic scaling)
- **VALUE:** High — the official `confidence` field is only meaningful if it's an actual probability, not a raw, uncalibrated score.
- **EFFORT:** Low — a validation-split fit per detector, already fully specified.
- **RISK:** Low.
- **DEPENDENCIES:** A trained model and validation split per detector.
- **DEMO IMPACT:** Medium — judges may not directly probe calibration quality, but confidence values that look sensible (not clustered at 0.99 for everything) matter for credibility.
- **Tier: 2 (REQUIRED FOR WORKING MVP).**

### SHAP Explanations
- **VALUE:** Medium — deeper per-prediction transparency, appealing for an explainable-AI angle, but the already-designed template+evidence explanation satisfies the official evidence requirement without it.
- **EFFORT:** Medium — extra integration, dashboard rendering not currently designed.
- **RISK:** Medium — added per-alert latency if computed live threatens the bounded-latency requirement; an extra dependency.
- **DEPENDENCIES:** The tree-based MVP models (already exist); a UI component not yet designed.
- **DEMO IMPACT:** Medium-high if shown well ("here's exactly why the model flagged this" is a strong moment), but risky to build reliably under time pressure.
- **Tier: 4 (OPTIONAL ADVANCED), borderline 3** — see Part 3 for the conditional recommendation.

### Pluggable Detectors
- **VALUE:** Low for judging — judges care whether the seven threats work, not whether adding an eighth later is architecturally elegant.
- **EFFORT:** Medium-high — a clean plugin interface is real design work.
- **RISK:** Medium — premature abstraction risks slowing down getting the concrete seven detectors working.
- **DEPENDENCIES:** Stable per-threat detection modules (already exist informally).
- **DEMO IMPACT:** Very low — not visually demoable; a one-line architecture-diagram mention costs nothing.
- **Tier: 5 (FUTURE/PRODUCTION).**

### Analyst Feedback
- **VALUE:** Low-medium for the demo itself, but shows SOC-workflow awareness.
- **EFFORT:** Low — already fully designed (one entity, one endpoint, one UI button).
- **RISK:** Low.
- **DEPENDENCIES:** Alert Detail page and feedback endpoint (both already designed).
- **DEMO IMPACT:** Low-medium — an easy, low-cost line to include in a demo narrative.
- **Tier: 4 (OPTIONAL ADVANCED), but cheap enough to justify building** — see Part 3.

### Incident Correlation
- **VALUE:** Medium-high conceptually (grouping recon → DDoS, or tunnelling → exfiltration, into one incident is a compelling "we think like a SOC" story).
- **EFFORT:** High — requires cross-detector, cross-time reasoning that has never been designed (already noted in the alert-architecture task).
- **RISK:** High — a half-built correlation feature that groups things wrong looks worse in a demo than not having it at all.
- **DEPENDENCIES:** A stable, working alert stream from most/all seven detectors first.
- **DEMO IMPACT:** Potentially high if done well; high risk of visibly backfiring if rushed.
- **Tier: 5 (FUTURE/PRODUCTION)** — already correctly deferred in the alert-architecture task; reaffirmed here.

### Threat Timelines
- **VALUE:** Medium, but depends on correlation existing to mean anything beyond the already-planned alerts-over-time chart.
- **EFFORT:** Medium-high — inherits correlation's effort.
- **RISK:** Medium — same dependency risk as correlation.
- **DEPENDENCIES:** Incident correlation (not built).
- **DEMO IMPACT:** Medium, but largely redundant with Threat Analytics' already-planned visualizations until correlation exists.
- **Tier: 5 (FUTURE/PRODUCTION).**

### Integrity Verification (model + dataset hashing)
- **VALUE:** High relative to cost — protects the credibility of every ML claim the submission makes.
- **EFFORT:** Low — a hash field plus a comparison check, already precisely scoped in the security review.
- **RISK:** Low.
- **DEPENDENCIES:** Model-versioning scheme and experiment manifest (both already designed).
- **DEMO IMPACT:** Low-medium directly, but valuable if judges probe robustness/production-readiness thinking.
- **Tier: 2 (REQUIRED FOR WORKING MVP)** — already so classified in the security review.

### Tamper-Evident Alerts
- **VALUE:** Medium — a forensic-integrity story, appealing for a security-focused judging panel (NTRO context), but not required for the alert schema to function.
- **EFFORT:** Low-medium for a lightweight hash-chain field; high for full cryptographic anchoring.
- **RISK:** Low for the lightweight version.
- **DEPENDENCIES:** The alerts table (already designed).
- **DEMO IMPACT:** Medium — "even our alert log is tamper-evident" is a cheap, effective one-liner if the lightweight version exists.
- **Tier: 3 (HIGH-VALUE HACKATHON DIFFERENTIATOR)** for the lightweight version specifically; full cryptographic anchoring stays Tier 5.

### Deep Sequence Models (GRU, Temporal CNN, char-CNN)
- **VALUE:** Medium-high scientifically — this is the strongest "does ML add value beyond simple ML" story in the whole project, especially for encrypted-malware.
- **EFFORT:** High — sufficient labeled sequence data, training time, tuning, and integration within the latency budget.
- **RISK:** High — the encrypted-malware Temporal CNN specifically depends on the still-unresolved data gap; the C2 GRU adds real inference latency that threatens the bounded-latency requirement if not carefully implemented.
- **DEPENDENCIES:** Sufficient labeled sequence data per threat; the classical model already working as a fallback.
- **DEMO IMPACT:** High if it visibly beats the classical baseline in a side-by-side comparison — but that comparison itself takes dedicated time to build and validate reliably.
- **Tier: 4 (OPTIONAL ADVANCED).**

### Online Learning (from analyst feedback)
- **VALUE:** Medium conceptually, but carries a genuine **security** risk, not just an engineering one — online learning without careful safeguards can be poisoned by well-intentioned-but-wrong or adversarial feedback.
- **EFFORT:** High — a retraining pipeline, safety checks, and separate versioning for online-updated models.
- **RISK:** High, on two distinct axes (engineering complexity and model-poisoning risk).
- **DEPENDENCIES:** Analyst feedback (already designed) plus a retraining pipeline (not designed).
- **DEMO IMPACT:** Low — very hard to meaningfully demonstrate a model improving live within a short demo window.
- **Tier: 5 (FUTURE/PRODUCTION).**

### Horizontal Scaling
- **VALUE:** Low for judging — a single-host prototype meeting the committed throughput target doesn't need to actually scale horizontally to prove the concept.
- **EFFORT:** High — real distributed-systems engineering (partitioning, consumer-group rebalancing, cross-node state sharding).
- **RISK:** Medium — distracts from the core seven-threat detection work and introduces new failure modes with no corresponding demo benefit.
- **DEPENDENCIES:** The single-host pipeline working and benchmarked first.
- **DEMO IMPACT:** Very low — not visible in a live demo without an artificial multi-node setup that adds risk without adding a visible capability.
- **Tier: 5 (FUTURE/PRODUCTION)** — already correctly positioned as a documented upgrade path (Redis Streams → Kafka), not implementation work now.

---

## Part 3 — What to Build and What Not to Build for the First Complete Prototype

### Build
- All Tier-1 and Tier-2 items from Part 1 — these are the actual prototype: seven-threat rule+ML hybrid detection (with the two strategic calls below), the full runtime pipeline, alert schema, dashboard (Overview/Live Detections/Alerts/Alert Detail), replay mode, throughput demonstration, basic security hygiene, and model/dataset integrity hashing.
- **Calibrated confidence** — required, cheap, already fully specified.
- **Analyst feedback** — Tier 4 by strict category, but cheap enough (already fully designed, low effort) to include; recommended build.
- **Lightweight tamper-evident alert hash-chain** — the one Tier-3 differentiator worth its cost: cheap, self-contained, and a strong one-line story for a cybersecurity-themed hackathon judged in an NTRO context.
- **The rule-vs-ML comparison narrative** — not a "feature" to build so much as a presentation choice, but it costs nothing beyond what's already built (the rule baseline and the ML models both exist) and is one of the most scientifically credible differentiators available — make sure the demo/report actually shows this comparison rather than leaving it buried in documentation.

### Do Not Build
- Anomaly detection (Isolation Forest) — unresolved evidence-mapping gap, low demo payoff relative to effort.
- SHAP explanations — genuine appeal, but real latency/integration risk for a benefit the existing template+evidence explanation already substantially covers. If time is unexpectedly abundant, this is the single best candidate to revisit — but only computed offline/cached, never live per-alert.
- Pluggable detector architecture — the existing modular per-threat code structure already gives most of the real benefit informally; a formal plugin framework is premature abstraction.
- Incident correlation and threat timelines — both correctly already deferred; rushing either risks a demo-visible failure mode (wrongly-grouped alerts) that's worse than not having the feature.
- Deep sequence models (GRU, Temporal CNN, char-CNN) — keep fully documented as designed-but-deferred; the classical MVP models already deliver a reliable, demoable rule-vs-ML story at a fraction of the risk.
- Online learning — real security risk (feedback poisoning), not just an effort trade-off; defer entirely.
- Horizontal scaling — no demo benefit, real distraction risk from the work that actually matters for judging.
- RBAC, rate limiting, container hardening, full API abuse protection — correctly production-tier; a closed single-host demo doesn't need them to be credible.

### Two Strategic Calls, Restated Plainly
- **Encrypted-session malware:** given this task's explicit goal of maximum SIH value with minimum unnecessary complexity, the recommended path is to **formally descope this one threat from the MVP** rather than gamble remaining time on an unresolved data-acquisition problem — six threats fully working and honestly documented beats seven with one visibly broken during judging. This is a restatement of Correction 1 from the final audit, now made as an explicit build decision rather than left open.
- **DGA traffic-generation pipeline step:** unlike encrypted-malware, this is a small, well-scoped gap (a script that queries DGArchive-sourced domain names against the lab's internal resolver) — the fix is cheap relative to DGA's high differentiator value (a genuinely interesting entropy/n-gram ML story), so this one should be closed quickly rather than descoped.

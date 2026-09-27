# PS26145 — ML Architecture Formulation
**Scope:** Choose the detection architecture (how classifiers/models are organized relative to each other and to the rule baseline), not specific algorithms. Where a concrete algorithm is named, it is purely illustrative of a technique class, not a selection.

Grounding facts carried forward from prior tasks, since they drive this decision directly:
- The seven threats have **genuinely different statistical signatures** — DDoS/recon are magnitude/threshold-shaped; C2/encrypted-malware are sequence/shape-shaped; DGA/tunnelling/exfiltration sit in between (established in the threat-decomposition and rule-baseline tasks).
- **Severe class imbalance** is expected (benign ≫ each attack type), and is explicitly called out as a constraint the PS requires the system to handle.
- The PS requires **streaming, bounded-latency, near-real-time** operation with a **demonstrated throughput target**.
- The alert schema **requires supporting evidence** per alert — an explainability obligation, not optional polish.
- The rule baseline already showed a **wide spread in how much each threat needs ML** (DDoS/recon: rules go far; C2/encrypted-malware: rules are weak; DGA/tunnelling/exfiltration: in between).

---

## 1. Single Multiclass Classifier

One model, one shared feature space, predicts among {benign, ddos, c2, dga, dns_tunnelling, encrypted_malware, recon, exfiltration}.

| Criterion | Assessment |
|---|---|
| Detection quality | **Weak.** Forces DDoS's rate-magnitude features, C2's timing-sequence features, DGA's lexical features, and encrypted-malware's fingerprint/sequence features into one shared decision boundary. A model good at separating DDoS from benign on rate features has no reason to also be good at separating C2 from benign on periodicity features — this is exactly the heterogeneous-signature problem flagged up front. |
| Training complexity | Low-to-moderate — one training run, one dataset to assemble (though assembling one dataset that meaningfully covers all seven signatures at once is itself non-trivial). |
| Inference latency | Best-case low — a single model, single forward pass. |
| Explainability | Weak — a single shared model's decision boundary is harder to attribute to a specific interpretable cause per class; per-class evidence extraction (e.g., via SHAP) is possible but must be computed for whichever class the model output, adding a layer of indirection. |
| Class imbalance | **Worst-affected.** Seven attack classes plus benign, all competing for representation in one softmax — the minority classes (whichever attack types are rarest in the assembled dataset) will be hardest hit, and per earlier tasks, benign is expected to vastly outnumber every attack type simultaneously. |
| Extensibility | Poor — adding an eighth threat class later requires retraining the entire shared model and risks disturbing decision boundaries for the other seven. |
| Hackathon feasibility | Moderate — simplest single artifact to build, but the heterogeneous-feature-space problem above means it's likely to underperform in ways that are hard to fix quickly under time pressure. |

---

## 2. Specialized Binary Classifiers (one-per-threat)

Seven independent binary models (`threat_X` vs. `not threat_X`), each trained on its own feature subset from the earlier feature-engineering task.

| Criterion | Assessment |
|---|---|
| Detection quality | **Strong per-threat.** Each model's feature space and training data are tailored to that threat's actual statistical signature — the DDoS model only needs rate/flag/entropy features, the C2 model only needs periodicity/timing features, etc. This directly respects the heterogeneity finding. |
| Training complexity | **Highest of the simple options** — seven separate training pipelines, seven separate hyperparameter searches, seven separate evaluation passes. Genuinely more work, though each individual model is simpler than one shared model would need to be. |
| Inference latency | Requires running up to seven models per flow/session (though many can be skipped early — e.g., a DNS-only flow never needs the TLS-fingerprint model at all, giving natural short-circuiting). Aggregate latency is manageable if models are lightweight and routing is efficient, but is inherently higher than a single-model pass unless parallelized. |
| Explainability | **Strong** — each model's output is inherently tied to one threat's specific evidence fields, directly matching the alert schema's per-alert evidence requirement with no extra indirection. |
| Class imbalance | **Much better than option 1** — each binary model only has to separate one attack class from benign, a far more tractable two-class imbalance problem than a seven-way one, and imbalance-handling techniques (resampling, class weighting) can be tuned independently per threat based on that threat's actual severity of imbalance. |
| Extensibility | **Best of the simple options** — adding an eighth threat later means adding one new independent model, with zero retraining risk to the existing seven. |
| Hackathon feasibility | Moderate-to-good — more artifacts to build than option 1, but each is individually simpler (matches the rule-baseline's per-threat structure, which is already built and can inform each model's feature set directly). |

---

## 3. Hierarchical Detection

A first-stage coarse classifier (e.g., benign vs. any-attack, or grouped by "magnitude-based" vs. "sequence-based" threat family), followed by a second stage that specializes within whatever the first stage flagged.

| Criterion | Assessment |
|---|---|
| Detection quality | Potentially strong, but **introduces a compounding-error risk**: if the first stage misses an attack (false negative), no second-stage model ever gets a chance to catch it. Quality is bounded above by the first stage's recall. |
| Training complexity | **Highest overall** — must design and validate the grouping/taxonomy for the first stage in addition to training all second-stage specialists; the grouping decision itself is a nontrivial design problem (per the heterogeneity finding, a "magnitude vs. sequence" split roughly maps to the rule-baseline's viability split, but formalizing that split into a trainable first-stage target requires care). |
| Inference latency | Potentially **lower on average** than running all specialists on every flow (the first stage cheaply screens out most benign traffic before invoking expensive second-stage models) — a genuine latency advantage over option 2 for the common (benign) case. |
| Explainability | Moderate — the first stage's "why did this get escalated" reasoning is an extra layer to explain beyond the second stage's evidence, complicating the alert's evidence trail slightly. |
| Class imbalance | Reframes rather than solves it — the first stage still faces "rare attack vs. common benign," the same core imbalance problem, just with different class boundaries. |
| Extensibility | Moderate — adding a new threat means deciding which first-stage group it belongs to (or adding a new group), a design decision each time, not a drop-in addition. |
| Hackathon feasibility | **Weakest of the ML-only options for the available time** — the extra architectural layer (designing and validating the grouping, tuning the first-stage threshold's recall/precision trade-off, then building second-stage specialists on top) is more design and validation work than the timeline likely supports well. |

---

## 4. Rules + Classifiers (hybrid)

The already-built rule baseline runs as a fast first pass; ML models run either (a) only on what rules don't confidently resolve, or (b) in parallel with rules, with outputs combined per threat.

| Criterion | Assessment |
|---|---|
| Detection quality | **Strong, and directly informed by evidence already gathered** — the rule-baseline task showed exactly which threats rules handle well (DDoS, recon) versus poorly (C2, encrypted-malware). A hybrid can let rules carry the threats they're already good at and reserve ML effort for the threats that clearly need it, rather than forcing every threat through the same architecture. |
| Training complexity | **Lower than a pure specialized-classifier approach** — ML effort concentrates on the threats that most need it (C2, encrypted-malware, and the evasive cases of DGA/tunnelling/exfiltration), rather than building and tuning seven full ML models when two of them (DDoS, recon) may not need one at all to meet the bar. |
| Inference latency | **Good** — rule evaluation is cheap and can run first/always; ML inference is invoked selectively, reducing average per-flow compute versus running every specialist on every flow. |
| Explainability | **Strongest option overall** — rule-based alerts come with inherently interpretable evidence (the exact threshold crossed), and ML is reserved for cases where a learned score is genuinely necessary, keeping the overall system's evidence trail as simple as possible wherever simplicity suffices. |
| Class imbalance | Concentrating ML only where needed means the imbalance problem is faced only for the threats where it's unavoidable, rather than diluting model-tuning effort across all seven. |
| Extensibility | Good — new threats can start as a rule (fast to add) and graduate to an ML model later if the rule proves insufficient, a natural incremental path. |
| Hackathon feasibility | **Best of the ML-involving options** — the rule baseline already exists from the prior task; this option reuses it directly rather than treating it as throwaway scaffolding, and concentrates limited hackathon time on the two-to-three threats where the rule-baseline task already demonstrated ML is clearly needed. |

---

## 5. Ensemble (multiple models combined per threat, e.g., voting/stacking)

Two-or-more models per threat (or per feature-group) combined via voting, averaging, or a meta-learner.

| Criterion | Assessment |
|---|---|
| Detection quality | Can be **marginally higher** than a single specialized classifier per threat, if the ensemble members capture complementary error patterns — but the marginal gain is typically smaller than the gain from getting the *architecture* right in the first place (i.e., ensembling seven single-signature models is a refinement on top of option 2, not a substitute for it). |
| Training complexity | **High** — multiplies the option-2 training burden by the number of ensemble members per threat, plus tuning the combination/voting logic itself. |
| Inference latency | **Worst of the options considered** — running multiple models per threat, per flow, directly multiplies inference cost, working against the PS's bounded-latency/throughput requirements. |
| Explainability | Weaker — attributing a combined ensemble decision to specific evidence is harder than a single model's or a rule's direct evidence trail. |
| Class imbalance | No inherent improvement over option 2's per-threat imbalance handling — ensembling doesn't solve imbalance by itself, only mitigates variance. |
| Extensibility | Similar to option 2, with added complexity per threat. |
| Hackathon feasibility | **Weakest overall** — the marginal detection-quality benefit does not justify the added training time, tuning time, and latency cost within a hackathon timeline; this is a refinement appropriate for a later production iteration, not a first working prototype. |

---

## 6. Supervised Detection + Anomaly Detection (hybrid)

Supervised classifiers for threats with well-characterized attack samples (all seven, in this case, since the lab can generate labeled examples of each), plus an unsupervised/semi-supervised anomaly-detection layer to catch patterns not matching any known attack profile.

| Criterion | Assessment |
|---|---|
| Detection quality | **Adds a genuinely different capability** — the seven threats are officially required and all can be labeled from the lab, so supervised methods are the correct primary tool for all seven; anomaly detection would supplement by catching genuinely novel patterns the labeled data never anticipated (real-world zero-day variants). |
| Training complexity | Adds a **second, differently-shaped modeling problem** — anomaly detection requires its own baseline-definition and threshold-tuning work (what counts as "normal" per feature space) separate from and in addition to the supervised classifiers' training. |
| Inference latency | Adds another inference pass per flow if run in parallel with the supervised path, similar overhead concern to the ensemble option. |
| Explainability | Anomaly scores are typically **harder to explain** than a supervised classifier's class-specific evidence — "this doesn't look like anything normal" is a weaker evidence statement than "this matched the DDoS SYN-flood pattern," which works against the alert schema's evidence requirement. |
| Class imbalance | Anomaly detection is actually well-suited to extreme imbalance by design (it doesn't need labeled positive examples at all) — a genuine strength for any threat where labeled attack data is scarce. |
| Extensibility | Good in principle (anomaly detection doesn't need retraining to "learn" a brand-new attack shape it's never seen), but exactly how to fold a flagged anomaly into the PS's seven-class alert schema (what `threat_class` does an anomaly get?) is unresolved and would need explicit design. |
| Hackathon feasibility | **Weak for a first prototype** — since every one of the seven required threats already has labeled data available from the lab, the anomaly-detection layer would be solving a problem the current scope doesn't actually have yet (there's no "unknown" threat category the PS asks for), making it additional build effort without addressing an official requirement. Better suited as a noted *future/optional* enhancement (consistent with its placement in the earlier "optional enhancements" list) than as the prototype's core architecture. |

---

## Comparison Summary

| Architecture | Detection Quality | Training Complexity | Inference Latency | Explainability | Class Imbalance Handling | Extensibility | Hackathon Feasibility |
|---|---|---|---|---|---|---|---|
| 1. Single multiclass | Weak | Low-Moderate | Best-case low | Weak | Worst | Poor | Moderate |
| 2. Specialized binary | Strong per-threat | High | Moderate | Strong | Good | Best | Moderate-Good |
| 3. Hierarchical | Potentially strong, capped by 1st stage | Highest | Lower avg. (screening) | Moderate | Reframed, not solved | Moderate | Weakest |
| 4. Rules + Classifiers | Strong, targeted | Lower (focused effort) | Good | Strongest | Good (focused) | Good | **Best** |
| 5. Ensemble | Marginal gain over 2 | High | Worst | Weaker | No inherent gain | Moderate | Weakest |
| 6. Supervised + Anomaly | Adds novel-pattern capability | Adds a 2nd problem type | Added overhead | Weaker (anomaly side) | Anomaly side strong | Good, but schema-unclear | Weak (solves an unposed problem) |

---

## Recommendation: **Option 4 — Rules + Classifiers (hybrid), structured as per-threat specialists (Option 2) where a classifier is actually needed**

**Recommended formulation, precisely stated:** Keep the already-built rule baseline in the pipeline as the first-pass detector for every threat. For the threats the rule-baseline task already showed rules handle well (DDoS, reconnaissance), the rule remains the primary detector, with no separate ML model required to meet the PS's bar for those two classes. For the threats the rule-baseline task showed rules handle poorly or only partially (C2 beaconing, encrypted-session malware, and the evasive cases of DGA/DNS tunnelling/exfiltration), a **specialized binary classifier per threat** (i.e., Option 2's structure, but scoped only to where it's needed) runs alongside or after the rule, using the exact per-threat feature subset already defined in the feature-engineering task.

**Why this, over the alternatives:**

1. **It is the only option that directly uses evidence already produced**, rather than starting the ML-formulation decision from a blank slate. The rule-baseline task's per-threat viability findings (rules strong for DDoS/recon, weak for C2/encrypted-malware, mixed for the rest) map almost exactly onto where this architecture concentrates its ML effort — the decision isn't guessed, it's read off already-gathered evidence.

2. **It respects the heterogeneous-signature finding without paying for it everywhere.** A single multiclass model (Option 1) forces one shared decision boundary across signatures that don't share structure; full specialized-classifiers-everywhere (Option 2) respects the heterogeneity but spends equal training/tuning effort on threats (DDoS, recon) that don't need it. The hybrid gets heterogeneity-awareness for the threats that need it while saving hackathon time on the threats that don't.

3. **It best serves the PS's explicit explainability requirement.** The standardized alert schema mandates supporting evidence per alert; rule-based alerts are natively interpretable (the exact threshold crossed), and reserving ML for only the threats where a learned score is genuinely necessary keeps the system's overall evidence trail as simple and defensible as possible — an advantage the ensemble and anomaly-detection options actively work against.

4. **It manages class imbalance by concentration rather than dilution.** Rather than facing a seven-way (or worse, ensemble-multiplied) imbalance problem, imbalance-handling effort focuses only on the threats that actually need a classifier, where it can be tuned per-threat as the specialized-binary-classifier analysis above describes.

5. **It is the most defensible hackathon-feasible choice.** It reuses the rule baseline (already built, not thrown away), avoids the hierarchical option's compounding-error risk and taxonomy-design burden, avoids the ensemble option's multiplied training/latency cost for marginal gain, and avoids building an anomaly-detection capability the PS's seven-class, fully-labelable scope doesn't actually call for yet (that capability is better left as the noted future/optional enhancement it already was in the earlier requirements task).

6. **It directly produces the comparison the earlier baseline task was built to enable** ("this baseline will later be used to prove whether ML adds value") — because ML is only introduced where the rule baseline already showed a real gap, any ML model built under this architecture has a built-in, honest justification: it exists specifically where the non-ML baseline was shown to fall short, rather than being added everywhere on the assumption that ML is always better.

**What is deliberately left open by this recommendation** (per scope — no specific algorithm chosen): which exact classifier family suits each of the ML-requiring threats (e.g., whether C2's periodicity/sequence features and encrypted-malware's packet-size/timing sequences call for the same or different model families), how rule and classifier outputs are combined when both fire on the same flow, and the precise routing/short-circuiting logic between rules and classifiers in the streaming pipeline. These are the natural next design steps.

---

**No specific ML algorithms have been selected** — this document determines only the architectural formulation (how models relate to each other and to the rule baseline), per the agreed task scope.

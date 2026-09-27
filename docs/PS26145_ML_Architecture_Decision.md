# PS26145 — ML Formulation & Architecture Decision
**Scope:** Compare six candidate detection-system architectures and recommend one for the prototype. No specific algorithm is selected except where needed to illustrate a point (e.g., "a tree-based model" as an example, not a decision).

**Grounding constraint carried from earlier tasks:** the seven threats do not share one statistical signature. DDoS/reconnaissance are large-magnitude, fast, structurally simple (rate/fan-out). C2 beaconing and encrypted-session malware are sequence/shape-pattern problems (timing regularity, packet-size sequences) that rules were already shown to handle poorly. DGA/DNS tunnelling are lexical/statistical scoring problems. Exfiltration is a ratio/baseline-deviation problem. Any architecture decision has to be judged against this heterogeneity, not against an assumption that one signal shape fits all seven.

---

## 1. Candidate Architectures — Definitions

1. **Single multiclass classifier** — one model, one feature vector spanning all seven threats' features, outputs one of {benign, 7 threat classes}.
2. **Specialized binary classifiers** — seven independent one-vs-rest models, each trained only on the features relevant to its threat, each outputs benign-vs-this-threat.
3. **Hierarchical detection** — a staged structure, e.g. a coarse "is this suspicious at all" stage followed by a second stage that assigns a specific threat class only to flows the first stage flagged.
4. **Rules + classifiers (hybrid)** — the rule-based baseline (already designed) acts as a fast first-pass filter/triage; ML classifiers handle the cases rules are known to handle poorly, or refine/score what rules flag.
5. **Ensemble** — multiple models (could be multiple algorithm types, or multiple specialized models) combined via voting/stacking/weighting into a single decision per flow.
6. **Supervised detection + anomaly detection (dual-path)** — supervised classifiers for the six/seven known threat classes, running alongside an unsupervised/semi-supervised anomaly detector meant to catch behavior that doesn't match any known class (including, implicitly, novel/zero-day patterns).

---

## 2. Evaluation

### 2.1 Detection Quality

| Architecture | Assessment |
|---|---|
| Single multiclass | Weak fit here — forcing DDoS's rate-based signal and C2's sequence-based signal into one shared feature space and one decision boundary set means the model must learn seven qualitatively different problems simultaneously; this typically degrades minority-class performance the most (see class-imbalance discussion), and the PS's own six/seven-way heterogeneity argues against it. |
| Specialized binary | Strong fit — each model only has to learn one threat's specific signature using only its relevant features, directly matching the heterogeneity already documented. |
| Hierarchical | Strong fit for reducing false-positive volume (most traffic is benign and gets filtered at stage one cheaply), but detection quality for the fine-grained second stage still depends on what's used there — this option is really "how you organize inference," not a full answer by itself. |
| Rules + classifiers | Strong on the threats rules already handle well (DDoS, recon) and where ML is layered onto the threats rules handle poorly (C2, encrypted malware) — directly exploits the per-threat findings from the baseline task rather than treating all seven uniformly. |
| Ensemble | Can be strong, but the gain is typically marginal over a well-tuned single specialized model per threat, at real added cost (see training complexity, latency) — ensembling helps most when a single model type has a specific weakness the ensemble compensates for, which is a narrower justification than "ensemble everything." |
| Supervised + anomaly (dual-path) | Adds real, otherwise-unavailable value specifically against unknown/novel attack variants (something none of the other five architectures address at all) — but for the seven *known* classes the PS explicitly asks for, the anomaly path is a secondary signal, not the primary detector. |

### 2.2 Training Complexity

| Architecture | Assessment |
|---|---|
| Single multiclass | Lowest complexity to set up (one training pipeline, one dataset join) but hardest to tune well, since improving one class's performance can degrade another's within a shared decision boundary. |
| Specialized binary | Moderate — seven separate, simpler training pipelines, each easier to reason about and tune independently, at the cost of maintaining seven pipelines instead of one. |
| Hierarchical | Higher — requires coordinating two training stages and deciding what "stage one" should learn to flag as suspicious, which is itself a design decision with no single obvious answer. |
| Rules + classifiers | Low-to-moderate — the rule component requires no training at all (already built), so only the ML-covered subset of threats needs a training pipeline, meaningfully less work than training all seven from scratch. |
| Ensemble | Highest — requires training the base models *and* tuning the combination layer (voting weights/stacking model), plus more careful cross-validation to avoid the ensemble overfitting to quirks of the validation set. |
| Supervised + anomaly | High — two entirely different modeling paradigms (supervised classifiers, unsupervised anomaly model) must both be built, tuned, and then reconciled into one coherent alerting output. |

### 2.3 Inference Latency

| Architecture | Assessment |
|---|---|
| Single multiclass | One model, one forward pass per flow — lowest latency of any ML-only option. |
| Specialized binary | Seven models must each score every relevant flow — higher latency than a single model unless run in parallel, though each individual model is simpler/faster than one large multiclass model would need to be. |
| Hierarchical | Potentially the *fastest in aggregate*, since most flows are benign and get rejected cheaply at stage one, only a minority pay the cost of stage-two scoring — directly relevant to the PS's bounded-latency requirement. |
| Rules + classifiers | Similarly favorable — rule evaluation is near-instant (simple threshold checks), so the majority of "obviously fine" or "obviously DDoS/recon" traffic never needs to reach a model at all; ML latency is only paid where it's actually needed (C2, encrypted malware, and the harder DGA/tunnelling/exfiltration cases). |
| Ensemble | Worst latency of the six — every base model must run for every flow before combination, directly working against the bounded-latency requirement. |
| Supervised + anomaly | Two parallel scoring paths per flow (classifier + anomaly model) — moderate-to-high latency, though the two paths could run concurrently rather than sequentially if infrastructure allows. |

### 2.4 Explainability

| Architecture | Assessment |
|---|---|
| Single multiclass | Hardest to explain per-alert — a single shared decision boundary across seven classes makes it harder to state cleanly "why did this flow trigger *this specific* class" without post-hoc explanation tooling (e.g., SHAP) doing most of the work. |
| Specialized binary | Easier — each model's decision is naturally scoped to one question ("is this DDoS or not"), and its own feature importances are inherently threat-specific, which maps directly onto the PS's required "supporting evidence" field per alert. |
| Hierarchical | Moderate — stage one's "suspicious or not" decision is coarse and less individually meaningful, though stage two (if built per-threat) inherits the same explainability as specialized binary. |
| Rules + classifiers | Best of the six for the rule-covered threats (a threshold crossing is maximally explainable — "rate exceeded X" is trivially stated as evidence) and still reasonably explainable for the ML-covered threats if those are built as scoped, specialized models rather than one large one. |
| Ensemble | Hardest to explain cleanly — a combined vote/stacked decision across multiple base models is inherently harder to reduce to one clean evidence statement per alert than a single model's output. |
| Supervised + anomaly | The supervised path explains as well as its underlying classifiers; the anomaly path is structurally harder to explain ("this doesn't look like anything we've seen" is a much weaker evidence statement than a specific rule/feature threshold). |

### 2.5 Class Imbalance

Every SIH threat class is rare relative to benign traffic, and the specific severity of imbalance differs by threat (already noted in the requirements task).

| Architecture | Assessment |
|---|---|
| Single multiclass | Worst-suited — a single shared loss function must balance seven simultaneous imbalance problems of different severities, and standard mitigations (class weighting, resampling) applied globally can help one class while hurting another. |
| Specialized binary | Best-suited — each binary problem's imbalance can be addressed independently (different resampling ratios, different class weights, different decision thresholds per threat), matching each threat's actual imbalance severity rather than a one-size-fits-all setting. |
| Hierarchical | Moderate — stage one (suspicious vs. benign) is itself a large binary imbalance problem that can be tuned on its own terms; stage two's imbalance handling depends on how it's built. |
| Rules + classifiers | Favorable — rules don't suffer from class imbalance at all (they're not learned from a skewed sample), so the imbalance problem is confined to only the subset of threats routed to ML, reducing the overall imbalance-handling burden. |
| Ensemble | Depends entirely on the base models — doesn't inherently solve imbalance any better than its components do, and can be harder to tune since imbalance handling has to be coordinated across all the base models plus the combiner. |
| Supervised + anomaly | The supervised side has the same imbalance problem as specialized binary; the anomaly-detection side is, notably, *designed* for exactly this kind of extreme-rarity setting (many unsupervised methods assume the "normal" class dominates), so it has a genuine structural advantage for the rarest, hardest-to-label threats. |

### 2.6 Extensibility (adding an eighth threat class later)

| Architecture | Assessment |
|---|---|
| Single multiclass | Poor — adding a class means retraining the entire shared model and re-validating that it hasn't degraded the other seven classes' decision boundaries. |
| Specialized binary | Excellent — a new threat just means adding one more independent binary model; nothing about the existing seven models needs to change. |
| Hierarchical | Good — a new threat class can usually be added at stage two without disturbing stage one's general "suspicious or not" boundary, though this depends on stage one's coverage being genuinely threat-agnostic. |
| Rules + classifiers | Good — a new threat can be added as a new rule, a new specialized model, or both, independently of the existing seven; this is effectively inherited from whichever of "specialized binary" or "rules" the new threat resembles most. |
| Ensemble | Fair — adding a new base model is straightforward, but the combination layer typically needs retuning to properly weight the new model against the existing ones. |
| Supervised + anomaly | Good on the supervised side (same as specialized binary); the anomaly side, notably, needs no retraining at all to "cover" a genuinely new/unknown threat type, since it was never threat-specific to begin with — a real extensibility advantage for truly novel attacks. |

### 2.7 Hackathon Feasibility

| Architecture | Assessment |
|---|---|
| Single multiclass | Feasible to build quickly, but the tuning effort to avoid one class starving another under a shared loss function is a real risk against a tight hackathon timeline. |
| Specialized binary | Feasible, though building and validating seven separate pipelines is more total engineering work than one shared pipeline — a real time cost, offset by each individual model being simpler to get right. |
| Hierarchical | Moderate — the two-stage design decision itself takes time to get right, and testing that stage one doesn't inadvertently filter out real attacks before they reach stage two is an extra validation burden under time pressure. |
| Rules + classifiers | **Highest feasibility of the six** — the rule component is already fully designed and requires zero additional training time; ML effort is concentrated only where it's actually justified (C2, encrypted malware, and the harder cases within DGA/tunnelling/exfiltration), which is a smaller total scope than building ML for all seven threats from nothing. |
| Ensemble | Lowest feasibility — training complexity (§2.2) and the extra tuning/validation the combination layer requires make this the hardest to deliver credibly in a fixed hackathon window. |
| Supervised + anomaly | Moderate-to-low — building and validating two fundamentally different modeling approaches, then reconciling their outputs into one alerting scheme, is meaningfully more scope than the rules+classifiers hybrid for a similar overall benefit on the seven *known* classes (its main advantage — novel-threat coverage — is not what the PS's six/seven-class taxonomy explicitly asks for). |

---

## 3. Summary Comparison Table

| Criterion | Single Multiclass | Specialized Binary | Hierarchical | Rules + Classifiers | Ensemble | Supervised + Anomaly |
|---|---|---|---|---|---|---|
| Detection quality | Weak | Strong | Strong (structure-dependent) | Strong | Strong (marginal gain) | Strong + novel-threat bonus |
| Training complexity | Low | Moderate | Higher | Low–Moderate | Highest | High |
| Inference latency | Best (single model) | Higher (7 models) | Best in aggregate | Best in aggregate | Worst | Moderate–High |
| Explainability | Weakest | Strong | Moderate | Strongest | Weakest | Mixed |
| Class imbalance handling | Weakest | Strongest | Moderate | Favorable (scope-reduced) | Depends on base models | Strong (esp. rarest classes) |
| Extensibility | Poor | Excellent | Good | Good | Fair | Good + novel-class coverage |
| Hackathon feasibility | Feasible, risky tuning | Feasible, more total work | Moderate | **Highest** | Lowest | Moderate–low |

---

## 4. Recommendation

**Recommended architecture: Rules + Classifiers (hybrid), organized as a lightweight hierarchy — rule-based triage first, specialized ML models second, only for the threats where rules were already shown to be insufficient.**

This is explicitly a synthesis of options 3 and 4 rather than a rejection of hierarchy — the "rules first" stage *is* a coarse triage stage, and the ML layer behind it is built as **specialized per-threat models** (option 2's approach) rather than one shared classifier, for the reasons in §2.5–2.6. It is presented as one recommended architecture, not three, because these design choices are complementary rather than competing: the hierarchy defines *when* ML runs, "rules + classifiers" defines *what replaces what*, and "specialized" defines *how the ML layer itself is structured*.

**Why this specific combination, threat by threat, using findings already established:**

- **DDoS and reconnaissance** stay on the rule path as primary detectors (per the baseline task's own conclusion that rules are a legitimately strong fit here) — no ML latency or training cost is spent on threats that don't need it.
- **C2 beaconing and encrypted-session malware** — the two threats explicitly identified as requiring ML because their core signal is a sequence/shape pattern — get dedicated specialized models, each trained only on its own relevant features, sidestepping the class-imbalance and explainability problems a shared multiclass model would introduce.
- **DGA, DNS tunnelling, and exfiltration** — the "rules catch the obvious case, degrade on evasive cases" middle tier — run through the rule first (cheap, catches the unsophisticated instances immediately) with a specialized model as the second-line check specifically for what the rule doesn't confidently resolve, rather than paying full ML cost on every flow in these categories.

**Why not the alternatives, in one line each:**
- *Single multiclass* — actively fights the documented heterogeneity of the seven threats and is the weakest option on both class imbalance and explainability, two of the PS's own stated concerns.
- *Pure specialized binary (no rules)* — reasonable, but discards the already-built, already-validated rule baseline and its latency/feasibility advantages for the two threats where rules are genuinely strong.
- *Pure hierarchical (no explicit rule/ML split)* — doesn't by itself specify what stage one or two should be; the recommended design effectively answers that open question using rules and specialized ML rather than leaving it undefined.
- *Ensemble* — worst latency and highest training complexity of the six, with only marginal expected detection-quality gain over well-tuned specialized models — a poor fit for a bounded-latency, fixed-timeline prototype.
- *Supervised + anomaly dual-path* — its unique advantage (catching genuinely novel/unknown attack types) is valuable but is not what the PS's six/seven-class official taxonomy asks the prototype to solve first; it is a strong **future-work candidate** (already listed as an "optional enhancement" in the requirements task — "anomaly detection layer for unknown/zero-day threats") rather than the prototype's primary architecture.

**Net effect against the evaluation criteria:** this recommendation scores best-or-tied-for-best on hackathon feasibility, inference latency, explainability, and class-imbalance handling, and is competitive (not the single best, but close) on detection quality and extensibility — the only criterion where it's clearly not the top performer is training complexity relative to a bare single multiclass model, which is an acceptable tradeoff given that option's other weaknesses.

---

**No specific ML algorithms have been selected in this document** — references to "a tree-based model" or similar are illustrative only. Algorithm choice for each specialized model remains a later, separate decision.

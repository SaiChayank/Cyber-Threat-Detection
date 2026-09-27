# PS26145 — Detection Output & Evidence Architecture
**Scope:** The alert itself — schema, confidence vs. severity separation, evidence generation, deduplication, and whether correlation belongs in the MVP. No dashboard/UI rendering design happens here; this defines the data contract a dashboard would later consume.

---

## 1. Field Classification

### OFFICIAL FIELDS
(Verbatim from the SIH listing's required alert schema — Source of Truth §5/§8)

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | ISO 8601 UTC datetime | When the alerted condition occurred/was observed |
| `flow_id` | string | Identifier of the flow (or entity/session) the alert concerns, per the canonical `FlowRecord.flow_id` |
| `threat_class` | enum | One of the seven official threat categories, or a rule-derived sub-type |
| `confidence` | float [0.0–1.0] | How confident the system is that this is a true positive |
| `supporting_evidence` | structured object | The specific feature values/observations justifying the alert |

### DERIVED REQUIRED FIELDS
(Not named verbatim in the SIH text, but necessary for the alert to actually function as an alert, given decisions already made in prior approved tasks — required for the system to work correctly, not optional polish)

| Field | Type | Meaning | Why required |
|---|---|---|---|
| `alert_id` | string (UUID or hash) | Unique identifier for this specific alert instance | Distinct from `flow_id` — one flow/entity could reasonably produce more than one alert over time (e.g., a long-lived C2 pair re-triggering); needed for deduplication (§6) and any future correlation (§7) |
| `detection_timestamp` | ISO 8601 UTC datetime | When the *system* generated the alert (as opposed to `timestamp`, when the underlying condition occurred) | These two times can differ — e.g., a long-horizon C2 window closes and the alert fires minutes after the earliest contributing packet arrived. Conflating them would misrepresent the system's actual detection latency, which matters for the bounded-latency requirement |
| `detector_type` | enum (`rule`, `ml`, `hybrid`) | Which layer of the hybrid architecture produced this alert | Needed because confidence is derived differently depending on the source (§3) — a consumer of the alert (dashboard, analyst, or evaluator) needs to know which |
| `model_version` | string, nullable | The specific trained-model version (per the model-versioning scheme) that produced an ML-derived verdict; null for pure rule-based alerts | Required for the auditability intention already established in the model-development methodology — an alert should be traceable to the exact model that generated it |
| `severity` | enum (`low`, `medium`, `high`, `critical`) | Operational urgency, distinct from statistical confidence (§3) | Required because confidence alone doesn't tell a SOC analyst how urgently to act (§4) |
| `src_ip` / `dst_ip` / `src_port` / `dst_port` / `protocol` | per canonical FlowRecord types | The actual network identity the alert concerns | An analyst cannot act on a flow ID alone without knowing what it refers to — this is the minimum addressing context every alert needs |
| `explanation` | string (human-readable) | A generated natural-language summary of why this alert fired | The PS's dashboard requirement implies human consumption; raw evidence values alone (§2) are necessary but not sufficient for a fast SOC read (§5) |
| `sub_type` | string, nullable | Rule-derived finer-grained classification within a threat class (e.g., "SYN flood" within `ddos`) | Established in the rule-baseline task's decision logic; carrying it through preserves diagnostic detail the rule already computed |
| `completeness_flag` | boolean/enum | Whether this alert's underlying window was computed over possibly-incomplete data (per the feature-engineering task's §9.2 design) | An analyst (or an automated downstream consumer) should be able to discount or double-check an alert known to be based on partial data |

### OPTIONAL FIELDS
(Useful, not required for MVP correctness; consistent with the earlier optional-enhancements classification)

| Field | Type | Meaning |
|---|---|---|
| `correlation_id` | string, nullable | Groups this alert with related alerts into a suspected incident — see §7 for why this is deferred |
| `raw_feature_snapshot` | structured object | The full feature vector at alert time, beyond just the evidence subset — useful for offline debugging/model improvement, not needed for the alert's own operational purpose |
| `analyst_feedback` | object, nullable | True/false-positive feedback an analyst later attaches — this is the "online learning from analyst feedback" capability already flagged as optional in the requirements task |
| `experiment_id` | string, nullable | Lab-context traceability (only populated in replay/lab-evaluation mode, per the runtime pipeline's replay design; absent in a genuine live/production alert) |

---

## 2. Model Confidence vs. Threat Severity — Kept Explicitly Separate

These answer two different questions and must never be collapsed into one number:

- **`confidence`** answers: *"How sure is the system that this classification is correct?"* — a statistical/calibrated quantity (§3), independent of how bad the underlying threat would be if true.
- **`severity`** answers: *"If this alert is correct, how urgently does it need attention?"* — an operational/risk quantity (§4) that factors in confidence but is not identical to it.

A concrete illustration of why conflating them would be wrong: a **high-confidence** reconnaissance alert (the system is very sure a scan occurred) might still be **low severity** (a scan alone, with no follow-on activity, is a minor nuisance) — whereas a **medium-confidence** data-exfiltration alert might warrant **high severity** (even a moderately-confident signal of data leaving the network deserves urgent attention given the potential impact). Collapsing these into one field would force an analyst to guess which meaning a given number represents.

---

## 3. Confidence Calibration Usage

- **For ML-derived verdicts:** the raw classifier score is passed through the calibration function (Platt scaling or isotonic regression, per the approved model-development methodology, fit on the validation split for that specific detector/model version) before being placed in `confidence`. The calibration mapping used is implicitly identified via `model_version`, so a given alert's confidence value is always traceable back to exactly which calibration curve produced it.
- **For rule-only verdicts** (DDoS/reconnaissance's primary path): confidence is **not** a learned probability, since no model produced it — it uses the **staged confidence values** already defined in the rule-baseline task (e.g., 0.6 if only the primary threshold fired, 0.9 if a corroborating sub-signal also fired). This is explicitly a simpler, rule-derived stand-in for probability, and `detector_type = rule` signals to any consumer that this confidence has a different statistical character than a calibrated ML score.
- **For hybrid verdicts** (a rule fires and its corroborating ML classifier also fires on the same underlying flow/entity — e.g., DDoS's rule-primary path plus its Random Forest corroboration): the two confidences are combined via a simple, explainable rule rather than an opaque fusion — specifically, **take the maximum of the two**, on the reasoning that either signal independently crossing its own bar is sufficient evidence, and using the max avoids a weaker signal diluting a strong one. This combination logic is deliberately simple for the prototype; a learned fusion model is a plausible future refinement, not designed here.

---

## 4. Severity Calculation

Kept deliberately simple for the prototype — a transparent, explainable formula rather than a second learned model:

```
severity_score = base_weight(threat_class) × confidence_tier_multiplier(confidence) × magnitude_factor(evidence)
```

- **`base_weight(threat_class)`** — a fixed, documented per-threat weight reflecting typical real-world impact if the alert is a true positive (e.g., data exfiltration and encrypted-session malware weighted higher than reconnaissance alone, consistent with how a SOC would typically triage). These weights are a team-authored, explicitly documented starting point — not derived from any dataset, and stated as such rather than dressed up as empirically tuned.
- **`confidence_tier_multiplier(confidence)`** — a step function (e.g., low/medium/high confidence bands map to increasing multipliers), so severity scales with how sure the system is, without making severity *equal to* confidence.
- **`magnitude_factor(evidence)`** — how extreme the underlying evidence is relative to its threshold (e.g., a flood at 50× the rate threshold vs. barely over it; an exfiltration ratio far beyond the ratio threshold vs. marginally over) — this uses values already computed during feature extraction/rule evaluation, not a new computation.
- The resulting `severity_score` is bucketed into the four `severity` enum values (`low`/`medium`/`high`/`critical`) via documented cutoffs.

**Explicitly out of scope for this design:** any notion of *asset criticality* (e.g., "this destination is a production database, weight it higher") — no asset-inventory or asset-value system has been designed anywhere in this project, so severity here is threat-intrinsic only, not context-of-target-aware. This is a real limitation worth stating plainly rather than implying a completeness the design doesn't have; asset-aware severity weighting is a natural but undesigned future enhancement.

---

## 5. Explanation Generation

- **Template-based, not free-form generation.** For each threat class, a fixed human-readable template is filled in with the alert's own already-computed evidence values — e.g., for DDoS: *"Destination {dst_ip} received {dst_packet_rate} packets/sec (threshold: {threshold}), with {syn_no_completion_ratio:.0%} of connections showing incomplete SYN handshakes."*
- **Why templates, not an LLM-generated summary, for the MVP:** a template is fast (no added inference latency, directly compatible with the bounded-latency requirement), fully deterministic and auditable (the exact same evidence always produces the exact same sentence), and — critically for a security tool — **cannot fabricate details**, since it only ever inserts already-computed, already-verified values into fixed slots.
- **If a more natural-language summary is desired later** (explicitly a future/optional enhancement, not MVP): an LLM could be used to paraphrase the template output into smoother prose, but only ever as a rewording layer constrained to the exact evidence values already present — never given free rein to add or infer detail — since a hallucinated fact in a security alert's explanation would be actively harmful (an analyst acting on a fabricated detail is a real safety concern, not a cosmetic one). This constraint is stated as a requirement for any future implementation of this optional feature, not merely a suggestion.

**Per-threat human-readable evidence examples:**

| Threat | Example `supporting_evidence` (structured) | Example generated `explanation` |
|---|---|---|
| DDoS | `{dst_packet_rate: 84500, threshold: 5000, syn_no_completion_ratio: 0.91, unique_src_count: 3120}` | "Destination 10.99.0.12 received 84,500 packets/sec (threshold 5,000), with 91% of connections showing incomplete SYN handshakes from 3,120 distinct source IPs — consistent with a SYN flood." |
| C2 Beaconing | `{periodicity_score: 0.03, destination_repeat_count: 214, flow_size_consistency: 12.4}` | "Host 10.99.0.45 contacted 10.99.0.200 214 times with highly regular timing (variation score 0.03) and near-identical payload sizes — consistent with automated beaconing." |
| DGA Domains | `{sample_domains: ["xqjvbzpqrw.net", "ktmnzalpqe.net"], domain_char_entropy: 4.1, nxdomain_ratio: 0.87}` | "Host 10.99.0.31 queried 87% NXDOMAIN-resolving, high-entropy domain names (e.g., xqjvbzpqrw.net) — consistent with algorithmically generated domain lookups." |
| DNS Tunnelling | `{query_length_avg: 187, record_type: "TXT", record_type_fraction: 0.78, response_size_avg: 940}` | "Host 10.99.0.52's DNS queries to fakezone.lab averaged 187 characters, 78% using TXT records with unusually large (940-byte avg) responses — consistent with data being tunnelled over DNS." |
| Encrypted-Session Malware | `{ja3: "6734f37..." , ja3_rarity_score: 0.97, packet_size_prefix_variance: 3.2}` | "A TLS session from 10.99.0.60 used a rarely-seen client fingerprint (JA3 6734f37…, seen in <1% of recent traffic) with an unusually uniform packet-size pattern — consistent with malware traffic disguised as normal TLS." |
| Reconnaissance/Scanning | `{unique_dst_port_count: 812, scan_attempt_rate: 340, flow_completion_ratio: 0.04}` | "Host 10.99.0.77 attempted connections to 812 distinct ports on the target at 340 attempts/sec, with 96% of attempts incomplete — consistent with a port scan." |
| Data Exfiltration | `{outbound_inbound_byte_ratio: 46.2, cumulative_outbound_volume_mb: 2140, destination_novelty: true}` | "Host 10.99.0.19 sent 2,140 MB to a previously unseen destination with a 46:1 outbound-to-inbound byte ratio — consistent with data exfiltration." |

---

## 6. Alert Deduplication

- **Dedup key:** `(threat_class, primary_entity_key, time_bucket)`, where `primary_entity_key` is the relevant grouping identity per threat (e.g., `dst_ip` for DDoS/reconnaissance, `(src_ip, dst_ip)` pair for C2, `(host, domain)` for DGA/tunnelling, `session/flow_id` for encrypted-malware, `(src_ip, dst_ip)` for exfiltration) — reusing exactly the scoping already defined per-feature in the feature-engineering task, not a new concept.
- **Suppression policy:** the first alert for a given dedup key fires immediately once its threshold/classifier crosses the decision boundary. Subsequent triggering events for the **same key within a cooldown window** do not generate a new alert — instead, the existing alert is **updated in place** (extending its `timestamp` range, refreshing `supporting_evidence` with the latest values, and re-evaluating `severity` in case the magnitude has grown) rather than creating alert storms for one ongoing condition (e.g., a DDoS flood that lasts several minutes should produce one evolving alert, not one alert per second).
- **Escalation override:** if a subsequent event's `severity` would be meaningfully higher than the currently-suppressed alert's (e.g., the magnitude factor jumps sharply), a new alert is emitted despite the cooldown — an ongoing condition that suddenly gets much worse deserves fresh attention rather than silent absorption into an already-open, lower-severity alert.
- **Rule+ML dedup (from §3):** when both the rule and its corroborating classifier fire on the same underlying flow/entity within the same evaluation cycle, this is **one alert with `detector_type = hybrid`**, not two separate alerts — the combination logic in §3 already produces a single confidence value for exactly this reason.

---

## 7. Optional Correlation

**Decision: Correlation belongs LATER, not in the MVP.**

**Reasoning:**
- The official alert schema requirement is satisfied entirely by the per-alert structure defined above — nothing in the SIH text requires grouping alerts into incidents, only that each alert individually carry timestamp/flow ID/threat class/confidence/evidence.
- Correlation was already placed in the **optional-enhancements** list during the original requirements-analysis task ("threat correlation engine — grouping related alerts into one incident"), not the required-functionality list — this decision is consistent with, not a new judgment against, that earlier classification.
- Correlation is a genuinely harder problem than it might first appear: meaningfully linking, say, a reconnaissance alert followed by a DDoS alert from the same source, or a DNS-tunnelling alert followed by an exfiltration alert from the same host, requires cross-detector, cross-time reasoning that has not been designed anywhere in this project (no shared incident-identity model, no time-window-for-relatedness policy, no confidence-of-correlation concept) — attempting it now would mean under-designing a second hard problem instead of finishing the first one well.
- The schema **leaves room for it** (`correlation_id`, nullable, in the optional fields) precisely so that adding correlation later is an additive change — populating a field that already exists — rather than a schema-breaking change to whatever's already built and demoed.

---

## 8. Final Alert Contract / Schema

```json
{
  "alert_id": "string (UUID)",                     // DERIVED REQUIRED
  "timestamp": "ISO 8601 UTC datetime",             // OFFICIAL
  "detection_timestamp": "ISO 8601 UTC datetime",   // DERIVED REQUIRED
  "flow_id": "string",                              // OFFICIAL
  "threat_class": "enum[ddos|c2_beaconing|dga_domains|dns_tunnelling|encrypted_malware|reconnaissance|data_exfiltration]", // OFFICIAL
  "sub_type": "string | null",                      // DERIVED REQUIRED
  "confidence": "float [0.0-1.0]",                  // OFFICIAL
  "severity": "enum[low|medium|high|critical]",     // DERIVED REQUIRED
  "detector_type": "enum[rule|ml|hybrid]",          // DERIVED REQUIRED
  "model_version": "string | null",                 // DERIVED REQUIRED
  "src_ip": "string",                               // DERIVED REQUIRED
  "dst_ip": "string",                               // DERIVED REQUIRED
  "src_port": "integer | null",                     // DERIVED REQUIRED
  "dst_port": "integer | null",                     // DERIVED REQUIRED
  "protocol": "integer (IANA protocol number)",     // DERIVED REQUIRED
  "supporting_evidence": {                          // OFFICIAL (object; per-threat internal shape per §5 table)
    "...": "threat-specific key/value evidence fields"
  },
  "explanation": "string (human-readable)",         // DERIVED REQUIRED
  "completeness_flag": "boolean",                   // DERIVED REQUIRED
  "correlation_id": "string | null",                // OPTIONAL
  "raw_feature_snapshot": "object | null",          // OPTIONAL
  "analyst_feedback": "object | null",              // OPTIONAL
  "experiment_id": "string | null"                  // OPTIONAL
}
```

---

**No dashboard/UI rendering of this schema has been designed here** — this document defines the alert data contract only; how it is displayed, filtered, or drilled into is a later, explicit task.

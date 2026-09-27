# PS26145 — Dataset Evaluation & Data Portfolio Decision
**Scope:** Evaluate candidate data sources against the data requirements already established. No feature engineering or model design here — this is a source-selection decision only.

Evaluation order follows the mandated priority: official SIH-named tools first; public datasets considered only where they genuinely supply required fields the self-generated traffic can't easily cover, not to pad the portfolio.

---

## PART A — Official SIH-Named Tools

### A1. iperf3 (benign)
- **Threat coverage:** N/A — benign traffic generator.
- **Format:** Live traffic capturable as pcap/flow records at the mirror point; no pre-built dataset file, generated on demand.
- **Available fields:** Full packet/flow fields (5-tuple, packet/byte counts, timing) since it's real traffic you generate and capture yourself.
- **Labels:** Self-assigned ("Benign") at generation time — trivial, fully controlled ground truth.
- **Usefulness:** High — produces clean, high-throughput baseline traffic; directly useful for establishing "normal" volume/rate baselines against which DDoS and exfiltration detectors are compared.
- **Limitations:** Traffic is synthetic bulk-transfer in nature — lacks the application-layer diversity (browsing, mixed protocols, varied session shapes) of real enterprise traffic, which is a documented weakness of synthetic benign baselines generally.
- **Leakage risk:** Low — you control generation and capture independently of attack generation, so no inherent label leakage, provided timing/IP ranges for benign vs. attack runs are properly separated.
- **Domain-shift risk:** Medium — iperf3's traffic "shape" is simple and repetitive; a model over-fit to it may not generalize to richer real benign traffic (over-fitting to a clean baseline is explicitly flagged as a risk in the PS's own supporting-doc limitations).
- **Decision:** **KEEP** — official tool, required for a self-consistent testbed, no substitute needed.

### A2. Ostinato (benign)
- **Threat coverage:** N/A — benign/general traffic generator (packet crafting and replay).
- **Format:** Same as above — generated traffic, captured locally.
- **Available fields:** Full packet-level control (custom headers, protocols, rates) — good for producing varied protocol mixes beyond iperf3's TCP/UDP throughput focus.
- **Labels:** Self-assigned, trivial.
- **Usefulness:** Medium-high — complements iperf3 by adding protocol/packet-shape diversity (useful for reducing the over-fitting risk noted above).
- **Limitations:** Still synthetic/crafted rather than organically generated from real applications; requires manual configuration effort to approximate realistic mixes.
- **Leakage risk:** Low, same reasoning as A1.
- **Domain-shift risk:** Medium — better than iperf3 alone for diversity, but still not real user behavior.
- **Decision:** **KEEP** — official tool, adds benign traffic diversity that iperf3 alone lacks.

### A3. TRex (benign)
- **Threat coverage:** N/A — high-performance stateful/stateless traffic generator.
- **Format:** Generated traffic; also useful specifically for demonstrating throughput at scale (relevant to the official throughput-target requirement).
- **Available fields:** Full packet/flow fields; supports realistic stateful flow simulation at high rates.
- **Labels:** Self-assigned, trivial.
- **Usefulness:** High specifically for the throughput-demonstration requirement — TRex is designed to generate traffic at line rate, making it the natural tool for the mandated "demonstrate flows/sec or Mbps" benchmark.
- **Limitations:** Higher setup complexity than iperf3/Ostinato; may be more infrastructure than a hackathon timeline needs if throughput testing is done at modest scale.
- **Leakage risk:** Low, same reasoning as A1.
- **Domain-shift risk:** Medium, same caveat about synthetic traffic realism.
- **Decision:** **KEEP (conditional)** — valuable specifically for the throughput benchmark; if time is short, iperf3 alone can substitute for basic volume, but TRex is the better-fit official tool for a credible throughput demonstration.

### A4. hping3 (SYN/UDP floods, spoofed-source)
- **Threat coverage:** Volumetric/protocol DDoS (SYN floods, UDP floods, spoofed-source floods) — direct, official match.
- **Format:** Generated attack traffic, captured as pcap/flow at the mirror point.
- **Available fields:** Full packet fields including TCP flags, TTL, spoofed source IPs — exactly the fields identified as required for DDoS detection.
- **Labels:** Self-assigned ("DDoS – SYN flood" / "DDoS – UDP flood" / "DDoS – spoofed") with precise timestamps for start/stop of each attack run — high-quality, low-noise ground truth.
- **Usefulness:** High — directly produces the primary required signal (flag ratios, rate spikes, TTL anomalies) with full control over intensity for testing detection sensitivity at multiple severities.
- **Limitations:** Tool-generated floods may look more "textbook" than a real adversary's obfuscated or ramped-up flood; won't capture more sophisticated modern reflection attacks (e.g., DNS/NTP/memcached amplification) unless explicitly configured for them.
- **Leakage risk:** Low if attack windows are clearly time-boxed and not accidentally overlapped with mislabeled benign capture.
- **Domain-shift risk:** Medium — real-world DDoS traffic (especially from botnets) may have more IP/timing diversity than a single-tool-generated flood; still reasonable for prototype-level validation.
- **Decision:** **KEEP** — official tool, directly matches the DDoS detector's required data.

### A5. Slowloris (slow HTTP exhaustion)
- **Threat coverage:** A DoS variant (application-layer exhaustion) — adjacent to, but not one of the PS's six explicitly required threat categories. It's most naturally treated as a **sub-case of volumetric/protocol DDoS**, though it's technically a low-and-slow, low-volume attack, which is a different behavioral signature (long-held connections, not high-rate floods).
- **Format:** Generated attack traffic.
- **Available fields:** Connection duration, incomplete-request patterns, flow persistence — useful evidence of a resource-exhaustion pattern distinct from volumetric flood signatures.
- **Labels:** Self-assigned, trivial.
- **Usefulness:** Medium — useful as a **negative/edge case** to test whether the DDoS detector, if tuned only to high-rate signatures, misses low-and-slow application-layer DoS. Good for robustness testing, not central to core threat coverage.
- **Limitations:** Doesn't map cleanly onto any of the six official threat classes by itself — using it as a labeled class risks scope creep beyond the PS's defined taxonomy.
- **Leakage risk:** Low.
- **Domain-shift risk:** Low-medium.
- **Decision:** **KEEP (as DDoS sub-case / robustness test), not as a separate labeled class** — generate and observe it, but fold it under the "Volumetric/Protocol DDoS" umbrella rather than inventing an eighth category not in the PS's scope.

### A6. dnscat2 (DNS tunnelling)
- **Threat coverage:** DGA/DNS tunnelling — direct, official match (explicitly named in the PS's dataset guidance).
- **Format:** Generated DNS tunnel traffic.
- **Available fields:** Query name, length, record type, response size, timing — exactly the required DNS-metadata fields.
- **Labels:** Self-assigned ("DNS tunnelling – dnscat2"), precise.
- **Usefulness:** High — directly produces the tunnelling signal at the DNS-metadata level, matching the detector's data requirements exactly.
- **Limitations:** One specific tool's encoding pattern; a model trained only on dnscat2's characteristic query shapes may not generalize to other tunnelling tools (e.g., iodine, DNS2TCP) without also including those.
- **Leakage risk:** Low if generation is clearly time/IP separated from benign DNS traffic.
- **Domain-shift risk:** Medium — tool-specific signatures risk narrow generalization; mitigated by also using iodine (A7) for variety, which the PS itself names.
- **Decision:** **KEEP** — official tool, core source for DNS tunnelling class.

### A7. iodine (DNS tunnelling)
- **Threat coverage:** Same as A6 — DNS tunnelling, official match.
- **Format:** Generated DNS tunnel traffic.
- **Available fields:** Same required DNS-metadata fields as A6.
- **Labels:** Self-assigned ("DNS tunnelling – iodine"), precise.
- **Usefulness:** High — provides a second tunnelling-tool signature, directly reducing the single-tool generalization risk noted for dnscat2.
- **Limitations:** Same general tool-specificity caveat; still only two tools' worth of tunnelling variety.
- **Leakage risk:** Low, same reasoning.
- **Domain-shift risk:** Medium, mitigated somewhat by combining with A6.
- **Decision:** **KEEP** — official tool, complements dnscat2 for tunnelling-class diversity.

### A8. DGA samples / DGArchive (DGA domains)
- **Threat coverage:** DGA domains — direct, official match.
- **Format:** Domain name lists (strings), not packet/flow captures by themselves — these must be turned into actual DNS query traffic by the team (querying the generated domain names from a test host) to produce the packet/flow-level data the detector needs.
- **Available fields:** Domain-name strings, and (from DGArchive specifically) typically the DGA family/malware association per domain — useful for sub-typing labels if desired, though sub-typing is not an official PS requirement.
- **Labels:** Domain-level label is inherent (from a known DGA family); flow-level labels must be assigned by the team when the domains are actually queried to generate traffic.
- **Usefulness:** High — this is the only named official source that gives GDA lexical patterns with realistic algorithmic diversity across many families, which is hard to approximate by hand.
- **Limitations:** DGArchive access/licensing terms should be checked before use (some DGA feed sources have usage restrictions); also, actually resolving these domains during traffic generation must be done carefully (e.g., in a sandboxed/controlled DNS environment) to avoid unintended external queries.
- **Leakage risk:** Low-medium — care needed that the *querying host* used to generate DGA traffic isn't reused in a way that correlates DGA-traffic timing with unrelated benign-traffic timing (a subtle leakage path if not separated).
- **Domain-shift risk:** Low for this specific class — DGArchive covers many real malware families, which is about as representative as a hackathon-scope project can get without exposure to live malware.
- **Decision:** **KEEP** — official tool/source, but flag the operational step (need to actually generate DNS query traffic from the domain list, not just use the string list directly) as a team task, not yet designed here.

### A9. Sandboxed C2 emulator (C2 beaconing)
- **Threat coverage:** Botnet C2 beaconing — direct, official match.
- **Format:** Generated beacon traffic (exact fields depend on which specific emulator is chosen — a "team decision" not yet made).
- **Available fields:** Beacon interval, destination pattern, payload size — the core required fields for periodicity-based detection, provided the chosen emulator supports configurable jitter/interval realism.
- **Labels:** Self-assigned ("C2 beaconing"), precise, provided beacon sessions are clearly time-boxed.
- **Usefulness:** High — this is the only named official source that can produce the long-horizon periodicity signature (many minutes/hours of regular contact) needed for this detector, which is hard to fake convincingly by hand.
- **Limitations:** "Sandboxed C2 emulator" is not a single named tool in the PS — which specific emulator to use is an open team decision (flagged, not resolved here). Realism of jitter/timing patterns depends heavily on emulator choice/configuration.
- **Leakage risk:** Low if beacon sessions are clearly time-boxed and don't overlap with unrelated benign long-duration sessions.
- **Domain-shift risk:** Medium — real botnet C2 channels vary widely in evasion sophistication (domain fronting, randomized jitter, fast-flux); a single emulator's pattern is a reasonable prototype-scope approximation, not a guarantee of real-world generalization.
- **Decision:** **KEEP** — official source, but specific emulator selection remains an open team decision (see prior "missing technical decisions" list).

---

## PART B — Public Datasets (considered only where they add genuinely missing fields/coverage)

### B1. CIRA-CIC-DoHBrw-2020 (DNS-over-HTTPS tunnelling)
- **Threat coverage:** DNS tunnelling — directly relevant, and notably **generated using dnscat2 and Iodine** (the same tools the official SIH guidance names), plus DNS2TCP, giving one additional tunnelling-tool variant beyond A6/A7. It also separately captures encrypted-DoH benign vs. malicious traffic, and non-DoH (plaintext) traffic.
- **Format:** CSV flow-level statistical/time-series features (packet size, count, duration, inter-arrival time) plus some header-level TLS metadata, already extracted — not raw pcap.
- **Available fields:** Flow duration, packet count/size statistics, inter-arrival timing statistics — overlaps well with the required timing/flow fields for the DNS-tunnelling detector, especially for the *DoH-tunnelling* variant of this threat (where the DNS layer itself is inside an encrypted HTTPS session, an important edge case flagged earlier as an "unavailable field" scenario under DoH).
- **Labels:** Two-layer labeling — DoH vs. non-DoH, then Benign-DoH vs. Malicious-DoH — well-documented and directly usable.
- **Usefulness:** **Directly useful for a specific gap:** the self-generated dnscat2/iodine traffic (A6/A7) is plaintext DNS tunnelling; this dataset additionally covers the case where tunnelling happens *inside* DoH, which is exactly the blind-spot scenario flagged earlier (DGA/tunnelling detectors losing DNS-query visibility under DoH). Including it lets the prototype at least acknowledge and partially address that edge case rather than silently ignoring it.
- **Limitations:** Documented dataset bias — original release is ~90% malicious/10% benign (a rebalanced variant exists but isn't the original); benign traffic generated from automated Top-10k website browsing may not reflect enterprise workloads; malicious traffic uses fixed transmission-rate ranges, so may not cover slower/burstier evasive tunnelling behavior; features are pre-extracted (CSV), not raw pcap, so it can't be re-processed with the team's own feature-extraction pipeline without re-deriving from scratch.
- **Leakage risk:** Low for the dataset itself (well-documented, externally generated, independent of the team's own generation runs) — but mixing it with self-generated data requires care that the two data sources don't get conflated in ways that let a model learn "which generator" rather than "which threat behavior" (a domain-shift/leakage hybrid risk, addressed by keeping them as clearly separated evaluation folds, not blended row-by-row).
- **Domain-shift risk:** Medium — real DoH resolvers/browsers differ from the four resolvers and two browsers used to build this dataset, but this is still a reasonable, well-cited, purpose-built external validation set.
- **Decision:** **KEEP (as a supplementary/validation set for the DoH edge case only)** — not a replacement for A6/A7, but a genuine addition covering a real, previously-identified gap (encrypted-DNS tunnelling). Use it to test/validate detector generalization beyond the two official tools, not as the primary training source for the whole tunnelling class.

### B2. CIC-DDoS2019 (DDoS)
- **Threat coverage:** Volumetric/protocol DDoS — directly relevant, covers reflection-based (LDAP, NTP, DNS, SNMP, MSSQL, NetBIOS, SSDP, TFTP, PortMap) and exploitation-based (SYN, UDP, UDP-Lag) attack types.
- **Format:** Pre-extracted flow-level CSV (via CICFlowMeter) plus original pcaps.
- **Available fields:** Extensive flow statistics (duration, packet/byte counts and rates, flag counts, inter-arrival statistics) — a superset of what's needed, though many fields go beyond what the PS's own detection basis (rate + entropy) requires.
- **Labels:** Per-attack-type labels with documented attack time windows — high-quality, well-cited ground truth.
- **Usefulness:** **Genuinely adds something hping3 alone does not:** reflection/amplification attack types (DNS, NTP, LDAP, SNMP amplification) that hping3 does not natively produce, giving broader DDoS sub-type coverage than the official tool alone. This directly fills a real gap (the PS explicitly lists "UDP reflection/amplification" as required coverage, which hping3 alone covers only partially).
- **Limitations:** Very large (tens of millions of rows) — likely needs subsampling for hackathon-scope compute/time; known class-imbalance skew (benign is a tiny fraction on each attack day, since each capture day is attack-dominated) requiring careful sampling rather than naive use; some documented feature-quality issues in early CICFlowMeter versions are noted in the literature.
- **Leakage risk:** Medium if blended carelessly with self-generated benign traffic — since benign volume in this dataset is very small per day, over-relying on its benign samples for training risks the model learning this dataset's specific benign "shape" rather than a general one; mitigated by using self-generated benign traffic (A1/A2/A3) as the primary benign source and treating this dataset's benign flows only as supplementary.
- **Domain-shift risk:** Low-medium for the attack side (attacks are protocol-driven and reasonably tool-agnostic); some domain shift on the benign side.
- **Decision:** **KEEP (supplementary, attack-side only)** — use specifically to extend DDoS sub-type coverage (reflection/amplification variants) beyond what hping3 alone produces; do not use its benign traffic as the primary "normal" baseline.

### B3. CTU-13 (Botnet C2)
- **Threat coverage:** Botnet C2 beaconing — directly relevant, real (not emulated) botnet C&C traffic from seven malware families.
- **Format:** Bidirectional NetFlow (Argus-generated) CSV, plus original pcaps for some scenarios.
- **Available fields:** 5-tuple, duration, protocol, direction, connection state, packet/byte counts, source bytes — covers the flow-level fields needed, though it lacks the fine-grained per-packet timing sequence some encrypted-malware analysis would want (not this threat's requirement, though — C2 beaconing mainly needs inter-arrival/repeat-destination patterns, which this dataset supports well).
- **Labels:** Background / Botnet / Normal, manually verified per scenario — well-established, widely cited ground truth.
- **Usefulness:** **Genuinely adds real-world realism** the sandboxed C2 emulator (A9) cannot: these are traces of actual malware families' live C2 behavior (2011 vintage), giving a real-world periodicity/timing distribution to validate against, rather than relying solely on one emulator's configured pattern.
- **Limitations:** Captured in 2011 — malware C2 techniques have evolved significantly since (domain fronting, fast-flux, encrypted C2 over legitimate cloud services), so this is a domain-shift risk for *recent* evasive techniques specifically, even though it's excellent for validating basic periodicity detection; large file size for the full pcap version (NetFlow-only version is more practical for hackathon scope).
- **Leakage risk:** Low — externally generated, independent of the team's own emulator traffic, good for held-out validation rather than blended training.
- **Domain-shift risk:** Medium-high for modern/evasive C2 specifically, low for basic periodicity-pattern validation.
- **Decision:** **KEEP (as a real-world validation/held-out set)** — use to sanity-check that the periodicity-based approach generalizes beyond the single sandboxed emulator's pattern, not as the sole or primary training source.

### B4. CSE-CIC-IDS2018 (general-purpose multi-attack IDS benchmark)
- **Threat coverage:** Nominally touches several categories (DDoS, botnet, brute-force, infiltration, web attacks) via a large enterprise-emulation testbed.
- **Format:** Flow-level CSV (CICFlowMeter, ~80 features per flow) plus pcaps; also exists in a slimmed 12-field NetFlow-v9 variant.
- **Available fields:** Extensive general flow statistics — but critically, **no DNS-metadata fields, no TLS/QUIC fingerprint fields (JA3/JA3S/JA4), and no DNS-tunnelling-specific traffic** — meaning it does not genuinely add anything for DGA, DNS tunnelling, or encrypted-malware detection, which are three of the six required categories.
- **Labels:** Per-attack-category labels, well-documented.
- **Usefulness:** **Low incremental value for this specific PS.** Its DDoS and botnet coverage overlaps with what A4/CIC-DDoS2019 (B2) and CTU-13 (B3) already cover more specifically and cleanly; its brute-force/web-attack/infiltration categories fall entirely outside the PS's six required threat classes and would be scope creep to include.
- **Limitations:** Very large, general-purpose, and not aligned to this PS's specific six-class taxonomy or its metadata-only/passive-observation framing (its infiltration and web-attack scenarios assume payload-level/application-layer visibility not consistent with this PS's constraints).
- **Leakage risk:** N/A — not being adopted.
- **Domain-shift risk:** N/A — not being adopted.
- **Decision:** **REJECT** — does not provide genuinely new required fields or coverage beyond what more targeted datasets (B2, B3) and official tools already supply; including it would add volume without adding capability, which the task explicitly says to avoid.

### B5. UNSW-NB15 (general-purpose IDS benchmark, includes reconnaissance category)
- **Threat coverage:** Nominally includes a "Reconnaissance" category (scanning) alongside DoS, exploits, worms, etc.
- **Format:** Flow-level CSV with ~49 features, plus pcaps.
- **Available fields:** Flow statistics including some fields relevant to fan-out/scan detection (connection counts, service diversity).
- **Labels:** Per-category labels including "Reconnaissance."
- **Usefulness:** **Low incremental value.** Reconnaissance/port-scanning is one of the easiest threat classes to self-generate with full label precision and full control over scan rate/fan-out pattern (using simple scanning tools against the team's own lab targets) — a general external dataset adds little that self-generation doesn't already provide more cleanly, and its other eight-plus attack categories are entirely out of scope for this PS.
- **Limitations:** Broad multi-category dataset misaligned with this PS's specific six-class taxonomy; would require discarding most of the dataset's content to extract just the recon-relevant rows.
- **Leakage risk:** N/A — not being adopted.
- **Domain-shift risk:** N/A — not being adopted.
- **Decision:** **REJECT** — reconnaissance/scanning is adequately and more precisely covered by direct self-generation (a scanning tool run against lab targets); this dataset would add dataset count without adding real capability, which the task explicitly says to avoid.

### B6. Public JA3/JA4-labeled malware-vs-benign TLS fingerprint corpora (general category, no single dataset evaluated by name)
- **Threat coverage:** Encrypted-session malware indicators.
- **Format:** Varies by source (some public malware-traffic-analysis feeds publish JA3 hashes tied to known malware families; quality and completeness vary widely and are not consolidated into one clean, license-clear benchmark the way the DDoS/botnet/DNS datasets above are).
- **Available fields:** Fingerprint hash plus loose family association; rarely includes the full packet-size/timing sequence data alongside the fingerprint in one clean package.
- **Labels:** Inconsistent quality across sources; many public JA3 lists are threat-intel feeds (fingerprint → "known bad" association) rather than labeled traffic captures suitable for supervised flow-level training.
- **Usefulness:** Low as a drop-in training source for this specific need — the required detector needs *session-level* packet-size/timing sequences paired with fingerprints, which loose public JA3 blocklists don't provide in a directly usable form.
- **Limitations:** No single well-cited, license-clear, PS-aligned public dataset was identified that cleanly provides both fingerprint and sequence-level features together for this exact task; using scattered threat-intel JA3 lists risks poor label quality and license ambiguity.
- **Leakage risk:** Unclear/unverifiable given inconsistent sourcing — a reason for caution, not adoption.
- **Domain-shift risk:** High and unquantifiable without knowing the specific source's collection methodology.
- **Decision:** **REJECT (for now)** — no genuinely fitting public dataset identified; this class will need to rely on self-generated encrypted sessions (benign TLS from iperf3/Ostinato-carried HTTPS-like traffic, or purpose-built encrypted malware emulation as a team decision) rather than an unverified public source. Flagging this as an open gap rather than papering over it with a weak dataset.

### B7. Public data-exfiltration-labeled datasets (general category)
- **Threat coverage:** Data exfiltration.
- **Format/availability:** No single well-established, widely-cited public benchmark specifically isolates "data exfiltration via asymmetric flow volume" as a clean standalone labeled class the way DDoS/botnet/DNS-tunnelling datasets do; exfiltration in most general IDS datasets is folded into broader "infiltration" categories that also involve other attack steps.
- **Usefulness:** Low — self-generation (large controlled outbound transfers vs. normal traffic, using the same benign generators already in the portfolio) gives cleaner, more directly-labeled, better-controlled ground truth than trying to extract an exfiltration-specific signal from a general-purpose multi-stage-attack dataset.
- **Decision:** **REJECT** — no genuinely fitting public dataset identified; rely on self-generated asymmetric-volume traffic (a team task, not designed here) instead.

---

## THREAT → REQUIRED DATA → PURPOSE (dataset-sourcing view)

| Threat | Primary Source(s) | Purpose |
|---|---|---|
| DDoS (SYN/UDP/spoofed) | hping3 (A4, primary) + CIC-DDoS2019 (B2, supplementary — reflection/amplification variants) + Slowloris (A5, robustness edge case) | Generate core flood signatures with full label control; extend to reflection-type attacks not natively covered by hping3 |
| C2 Beaconing | Sandboxed C2 emulator (A9, primary) + CTU-13 (B3, real-world validation) | Generate controllable, precisely-labeled beacon traffic; validate periodicity approach against real historical malware behavior |
| DGA Domains | DGArchive / published algorithms (A8, primary) | Provide lexically diverse, realistic algorithmic domain patterns across many malware families |
| DNS Tunnelling | dnscat2 (A6) + iodine (A7), primary + CIRA-CIC-DoHBrw-2020 (B1, supplementary — DoH-encrypted tunnelling edge case) | Generate plaintext tunnelling signal from two distinct tools; additionally cover the DoH-encrypted blind-spot scenario flagged earlier |
| Encrypted-Session Malware | Self-generated only (gap — no adopted public source) | Session-level JA3/JA3S/JA4 + packet-size/timing data must be built by the team; flagged as open work, not solved by an external dataset |
| Reconnaissance/Scanning | Self-generated only (direct scanning tool against lab targets — specific tool a team decision) | Full control over fan-out rate/pattern with precise ground truth; no external dataset adds value here |
| Data Exfiltration | Self-generated only (controlled asymmetric-volume transfers) | Full control over volume/ratio patterns with precise ground truth; no external dataset adds value here |
| Benign baseline (all detectors) | iperf3 (A1) + Ostinato (A2) + TRex (A3, also for throughput demo) | Establish "normal" traffic baseline across volume, protocol diversity, and throughput-scale scenarios |

---

## Final Dataset Portfolio for the Prototype

**Primary (official, self-generated — the backbone of the training/eval data):**
1. iperf3, Ostinato, TRex → benign baseline + throughput demonstration
2. hping3 → DDoS (SYN/UDP/spoofed)
3. Slowloris → DDoS robustness edge case (folded into DDoS class, not a separate label)
4. dnscat2, iodine → DNS tunnelling
5. DGArchive / published DGA algorithms → DGA domains (requires a team-built step to turn domain lists into actual queried traffic)
6. Sandboxed C2 emulator (specific tool TBD — open team decision) → C2 beaconing

**Supplementary (public, used narrowly for specific validated gaps — not primary training sources):**
7. CIRA-CIC-DoHBrw-2020 → DoH-encrypted DNS tunnelling edge case
8. CIC-DDoS2019 (attack-side only) → reflection/amplification DDoS sub-types not covered by hping3
9. CTU-13 → real-world C2 periodicity validation/held-out check

**Explicitly rejected:**
- CSE-CIC-IDS2018 — no genuinely new required fields/coverage over what's already sourced
- UNSW-NB15 — reconnaissance already better covered by self-generation
- Public JA3/JA4 blocklist corpora — no clean, well-labeled, license-clear source found; treated as an open gap for the encrypted-malware class rather than force-fit
- Public exfiltration-specific datasets — none well-established; self-generation preferred

**Open gap explicitly flagged (not solved by any dataset above):** Encrypted-session malware detection has no adopted external data source — self-generated encrypted sessions (benign HTTPS via existing generators, plus a purpose-built malicious-TLS emulation) will need to be designed as a team task. This is a real limitation to state plainly in documentation rather than obscure.

---

**No feature engineering or model design has been performed in this document** — this is a data-sourcing decision only, per the agreed task scope.

# PS26145 — Non-ML Baseline Detection System
**Scope:** Simple, explainable, rule/threshold-based detectors built directly on the features already defined — one purpose only: establish a credible baseline that any later ML system must beat. No ML model selection happens here.

Each baseline outputs the same structured alert shape already established as an official requirement (timestamp, flow/entity identifier, threat class, confidence score, supporting evidence) — for a rule-based system, "confidence" is necessarily a simpler construct than a model's probability output (see per-threat notes on how it's derived).

---

## 1. DDoS Baseline

**Input features:** `dst_packet_rate`, `dst_byte_rate`, `syn_no_completion_ratio`, `src_ip_entropy_toward_dst`, `unique_src_count_toward_dst`.

**Decision logic:**
```
IF dst_packet_rate > RATE_THRESHOLD
   OR dst_byte_rate > BYTE_THRESHOLD
THEN
   IF syn_no_completion_ratio > SYN_RATIO_THRESHOLD
       → flag as "DDoS – SYN flood" for this destination
   ELSE IF src_ip_entropy_toward_dst > ENTROPY_THRESHOLD
       AND unique_src_count_toward_dst > FANIN_THRESHOLD
       → flag as "DDoS – volumetric/spoofed flood" for this destination
   ELSE
       → flag as "DDoS – generic volumetric" (rate alone was enough to trip the primary threshold)
```
**Output:** One alert per destination per triggering window, threat class `ddos` (with rule-derived sub-type label), confidence fixed by which sub-rule fired (see tuning note below), evidence = the specific feature values that crossed threshold.

**Threshold-tuning strategy:** Set `RATE_THRESHOLD`/`BYTE_THRESHOLD` from the *benign-only* traffic distribution generated in the lab (e.g., iperf3/Ostinato/TRex baseline runs) — pick a percentile (e.g., 99th) of observed benign rate as the floor, then validate against known-intensity hping3 runs to confirm separation. `SYN_RATIO_THRESHOLD`/`ENTROPY_THRESHOLD`/`FANIN_THRESHOLD` similarly calibrated from benign-vs-attack lab runs, not picked arbitrarily. Confidence can be a simple staged value (e.g., 0.6 if only the rate threshold fired, 0.9 if rate + a corroborating sub-signal fired) — a rule-based stand-in for probability, not a calibrated score.

**Expected weaknesses:** A single global rate threshold cannot adapt to a destination that legitimately receives variable load at different times of day; low-and-slow or below-threshold floods (deliberately paced to stay under the rate cutoff) evade detection entirely; thresholds tuned on lab-generated hping3 traffic may not transfer well to more sophisticated real-world flood shapes.

**Likely false positives:** Flash-crowd events, legitimate backup/sync jobs, CDN or load-balancer health-check storms, and any organically bursty benign service that happens to exceed the fixed rate threshold.

---

## 2. C2 Beaconing Baseline

**Input features:** `periodicity_score_pair`, `destination_repeat_count_pair`, `flow_size_consistency_pair`, `unique_destination_count_src`.

**Decision logic:**
```
IF destination_repeat_count_pair > REPEAT_THRESHOLD
   AND periodicity_score_pair < CV_THRESHOLD   (low coefficient of variation = regular timing)
   AND flow_size_consistency_pair < SIZE_VARIANCE_THRESHOLD
   AND unique_destination_count_src < FEWDEST_THRESHOLD  (host is not broadly chatty — narrows to a small destination set)
THEN
   → flag (src, dst) pair as "C2 beaconing candidate"
```
**Output:** One alert per flagged (src, dst) pair, threat class `c2_beaconing`, confidence derived from how far below threshold the periodicity score sits (closer to zero = more confident), evidence = inter-arrival histogram summary and repeat count.

**Threshold-tuning strategy:** Calibrate `CV_THRESHOLD` and `SIZE_VARIANCE_THRESHOLD` against the sandboxed C2 emulator's known beacon interval/jitter settings (multiple emulator runs at different jitter levels to find where legitimate periodic services start to overlap), and separately validate against benign periodic traffic (NTP, telemetry) to find where the two distributions diverge. `REPEAT_THRESHOLD` and `FEWDEST_THRESHOLD` tuned from how many repeats/how narrow a destination set are needed before a rule-based system stops mistaking incidental repeat contact for beaconing.

**Expected weaknesses:** A fixed CV threshold cannot distinguish well-jittered/evasive C2 (deliberately randomized intervals) from benign randomness; requires the long observation horizon defined earlier (hours+) before the rule has enough data to fire at all, meaning a genuinely fast-acting C2 channel could complete its objective before this baseline accumulates sufficient history; static allow-listing of known-benign periodic services is brittle and needs manual maintenance.

**Likely false positives:** NTP synchronization, OS/software telemetry and update-check pings, monitoring/health-check agents, scheduled backup or sync jobs — all of which are legitimately periodic, low-variance, and often narrow-destination, precisely the shape this rule is designed to catch.

---

## 3. DGA Domain Baseline

**Input features:** `domain_char_entropy`, `domain_ngram_score`, `nxdomain_ratio_host`, `query_rate_host`.

**Decision logic:**
```
FOR each DNS query:
   IF domain_char_entropy > ENTROPY_THRESHOLD
      OR domain_ngram_score < NGRAM_THRESHOLD  (low likelihood under the natural-language reference model)
   THEN mark this individual query as "DGA-like"

PER host, over the window:
   IF fraction of "DGA-like" queries > DGA_FRACTION_THRESHOLD
      AND nxdomain_ratio_host > NXDOMAIN_THRESHOLD
   THEN → flag host as "DGA activity candidate"
```
**Output:** One alert per flagged host per window, threat class `dga_domains`, confidence from how far entropy/n-gram score exceed threshold (aggregated across the flagged queries), evidence = sample of the specific flagged domain strings and the host's NXDOMAIN ratio.

**Threshold-tuning strategy:** `ENTROPY_THRESHOLD`/`NGRAM_THRESHOLD` calibrated against the DGArchive-sourced domain lists (known-DGA distribution) versus a corpus of legitimate domains (from the benign traffic generators' actual DNS activity) to find a separating point. `DGA_FRACTION_THRESHOLD`/`NXDOMAIN_THRESHOLD` tuned so that a single incidental high-entropy-looking legitimate domain doesn't trip the host-level flag by itself — requiring a sustained pattern, not one query.

**Expected weaknesses:** A single global entropy/n-gram threshold can't capture the full diversity of DGA families (some are deliberately dictionary-based/wordlist-style precisely to evade entropy-based detection); legitimate CDN/cloud-generated subdomains can score as "DGA-like" under a naive threshold; the n-gram reference model's quality and language-coverage directly bounds this rule's accuracy.

**Likely false positives:** CDN and cloud-load-balancer auto-generated subdomains, short-lived marketing/campaign domains, legitimately random-looking but benign API/service endpoint names.

---

## 4. DNS Tunnelling Baseline

**Input features:** `query_length_avg_host`, `query_length_max_host`, `record_type_distribution_host`, `response_size_avg_domain`, `query_concentration_host_domain`.

**Decision logic:**
```
IF query_length_avg_host > LENGTH_THRESHOLD
   OR record_type_distribution_host[TXT or NULL] > RECORDTYPE_FRACTION_THRESHOLD
THEN
   IF query_concentration_host_domain > CONCENTRATION_THRESHOLD  (queries dominated by one domain)
       AND response_size_avg_domain > RESPONSE_SIZE_THRESHOLD
   THEN → flag (host, domain) pair as "DNS tunnelling candidate"
```
**Output:** One alert per flagged (host, domain) pair, threat class `dns_tunnelling`, confidence from combined severity of length/record-type/concentration deviation, evidence = sample query names, record-type breakdown, and response-size statistic.

**Threshold-tuning strategy:** Calibrate directly against dnscat2 and iodine lab traffic (known tunnelling query-length and record-type distributions) versus benign DNS traffic from the lab's generators, using the dual-tool comparison to avoid overfitting the threshold to one tool's specific encoding pattern.

**Expected weaknesses:** Tunnelling tools that deliberately keep query lengths short and use common record types (A/AAAA) to evade length/record-type thresholds will not be caught by this rule; the concentration requirement can be evaded by a tunnel that spreads queries across multiple lookalike subdomains of the same parent domain in a way that dilutes the per-domain concentration count unless the rule is domain-suffix-aware (a design detail not resolved here).

**Likely false positives:** Legitimate services with heavy TXT-record usage (SPF/DKIM/domain verification lookups), verbose subdomains from legitimate multi-tenant SaaS platforms, CDN configuration-discovery mechanisms.

---

## 5. Encrypted-Session Malware Baseline

**Input features:** `ja3_identity` (against a static known/suspicious list), `ja3_rarity_score`, `packet_size_prefix_variance`, `interpacket_timing_prefix_variance`.

**Decision logic:**
```
IF ja3_identity IN known_malicious_fingerprint_list
THEN → flag session as "Encrypted malware – known fingerprint match" (high confidence)

ELSE IF ja3_rarity_score > RARITY_THRESHOLD
     AND (packet_size_prefix_variance < SIZE_VARIANCE_LOWBOUND
          OR interpacket_timing_prefix_variance < TIMING_VARIANCE_LOWBOUND)
THEN → flag session as "Encrypted malware – anomalous fingerprint + regular session shape" (lower confidence)
```
**Output:** One alert per flagged session, threat class `encrypted_malware`, confidence high for a direct blocklist match, lower/graded for the anomaly-only branch, evidence = JA3 hash, rarity score, and the size/timing variance values.

**Threshold-tuning strategy:** The blocklist branch requires curating/maintaining a known-malicious-fingerprint reference list (an explicit team task, not resolved here — and itself has to be built without any test-period data, per the earlier leakage discipline). The anomaly branch's thresholds are calibrated against the lab's benign-TLS baseline (from the internal HTTPS service traffic) versus the emulated malicious-TLS sessions, looking for where "unusually regular/robotic" session shape separates from normal application variability.

**Expected weaknesses:** This is explicitly the weakest rule-based candidate of the seven — a pure blocklist match only catches *known* fingerprints and is trivially evaded by any malware using a common/legitimate-looking JA3 (a well-documented technique); the anomaly branch is a very coarse two-variance heuristic that cannot capture the genuinely pattern-recognition nature of "does this session's shape resemble malware C2," which was already flagged as fundamentally a pattern-recognition problem, not a threshold problem, back in the threat-decomposition task.

**Likely false positives:** Legitimate low-bandwidth or automated clients (IoT devices, monitoring agents, scripted API clients) that produce naturally regular, low-variance session shapes; JA3 fingerprint collisions between known-malware families and legitimate applications sharing library/TLS-stack characteristics.

---

## 6. Reconnaissance / Port-Scanning Baseline

**Input features:** `unique_dst_port_count_src`, `unique_dst_host_count_src`, `scan_attempt_rate_src`, `flow_completion_ratio_src`.

**Decision logic:**
```
IF unique_dst_port_count_src > PORT_FANOUT_THRESHOLD
   OR unique_dst_host_count_src > HOST_FANOUT_THRESHOLD
THEN
   IF scan_attempt_rate_src > RATE_THRESHOLD
      AND flow_completion_ratio_src < COMPLETION_THRESHOLD  (mostly incomplete attempts)
   THEN → flag source as "Reconnaissance/scanning candidate"
```
**Output:** One alert per flagged source per window, threat class `reconnaissance`, confidence from how far fan-out counts exceed threshold, evidence = list of targeted ports/hosts and completion ratio.

**Threshold-tuning strategy:** Calibrate `PORT_FANOUT_THRESHOLD`/`HOST_FANOUT_THRESHOLD` from the lab's own scanning-tool runs at known scan speeds/breadths, cross-checked against legitimate multi-port/multi-host benign patterns (e.g., a load balancer's own health checks across backend ports) to set the floor above normal operational fan-out.

**Expected weaknesses:** Slow/low-rate scans deliberately paced below the rate threshold, or scans spread across a very long time horizon (evading the short window this rule uses), will not be caught; a rule that only looks at fan-out and rate cannot distinguish a legitimate internal vulnerability-scanning tool (run by the organization itself) from a hostile scan without an allow-list.

**Likely false positives:** The organization's own authorized vulnerability/security scanners, load balancers or service-discovery mechanisms probing multiple backend ports/hosts, misconfigured clients retrying across a port range.

---

## 7. Data Exfiltration Baseline

**Input features:** `outbound_inbound_byte_ratio_flow`, `cumulative_outbound_volume_host`, `destination_novelty_flag`, `outbound_baseline_deviation_host`.

**Decision logic:**
```
IF outbound_inbound_byte_ratio_flow > RATIO_THRESHOLD
   AND destination_novelty_flag == TRUE
THEN → flag flow as "Exfiltration candidate – novel destination, asymmetric transfer"

ELSE IF outbound_baseline_deviation_host > ZSCORE_THRESHOLD
THEN → flag host as "Exfiltration candidate – volume deviates from established baseline"
```
**Output:** One alert per flagged flow or host, threat class `data_exfiltration`, confidence from the magnitude of ratio/deviation, evidence = byte ratio, cumulative volume, and novelty flag.

**Threshold-tuning strategy:** `RATIO_THRESHOLD` calibrated against the lab's simulated large-upload exfiltration scenario versus normal benign upload patterns (e.g., legitimate large file transfer via the benign generators) to find a separating ratio. `ZSCORE_THRESHOLD` tuned against each host's own EWMA baseline variability rather than a single global cutoff, since "normal" outbound volume genuinely differs by host/service.

**Expected weaknesses:** Exfiltration deliberately paced to stay within a host's normal-looking volume/ratio range (low-and-slow exfiltration) evades both branches; a single legitimate large-but-rare transfer (e.g., a genuine one-off backup) to a new destination will trigger the novelty-based branch as a false positive unless manually allow-listed; global ratio thresholds don't account for services that are inherently outbound-heavy by design (e.g., telemetry/logging uploads).

**Likely false positives:** Legitimate large uploads (cloud backup, video/content upload, software deployment pushes), inherently asymmetric-by-design protocols (streaming ingest, telemetry), and any first-time-but-legitimate business destination (a new vendor, a new cloud service).

---

## 8. Which Threats Are Reasonably Rule-Based vs. Clearly ML-Requiring

| Threat | Rule-based baseline viability | Reasoning |
|---|---|---|
| **DDoS** | **Reasonably viable as a standalone baseline.** | Rate thresholds and flag-ratio rules are a long-established, effective first line of defense for this threat class — the signal is large in magnitude and fast-onset, which suits simple thresholds well. This is the strongest rule-based candidate of the seven. |
| **Reconnaissance/Scanning** | **Reasonably viable as a standalone baseline.** | Fan-out counting is a classic, well-understood detection pattern; the core signal (one source touching many ports/hosts) is structurally simple and doesn't require learned pattern recognition to detect the *obvious* case, though evasive slow-scanning still needs more than a threshold. |
| **Data Exfiltration** | **Partially viable — good for the obvious case, weak for the evasive case.** | Ratio/volume thresholds catch blatant exfiltration well, but distinguishing genuinely unusual transfers from a host's own natural variability is fundamentally a baseline-modeling problem; a fixed global threshold underperforms an approach that actually learns per-host normal behavior. |
| **DGA Domains** | **Partially viable, clearly benefits from ML.** | Entropy/n-gram thresholds catch classic high-entropy DGA families reasonably well, but this is explicitly a scored/statistical judgment (as noted in the threat-decomposition task) rather than a clean rule — wordlist-based and hybrid DGA families are known to evade simple entropy thresholds, which is exactly where a learned classifier over richer lexical features adds real value. |
| **DNS Tunnelling** | **Partially viable, clearly benefits from ML.** | Length/record-type thresholds catch unsophisticated tunnels, but evasive tunnelling (short queries, common record types, spread across lookalike subdomains) requires the kind of multi-signal, learned-baseline-deviation reasoning a rule threshold can't express well. |
| **C2 Beaconing** | **Weak as a standalone baseline; clearly requires ML for anything beyond the obvious case.** | The core signal — regularity/periodicity — is inherently a *scored* statistical property, and jittered/evasive beaconing was already flagged as a known weakness of a fixed coefficient-of-variation threshold. A rule can catch textbook clockwork beacons but not adversarially-jittered ones; this is a strong candidate for demonstrating ML's added value. |
| **Encrypted-Session Malware** | **Weakest rule-based candidate of the seven; clearly requires ML.** | A pure fingerprint blocklist only catches *known* JA3 values and is trivially evaded; the underlying task — "does this encrypted session's shape resemble malware C2 vs. benign" — was already identified in the threat-decomposition task as fundamentally a pattern-recognition problem over packet-size/timing sequences, which a two-variance heuristic cannot meaningfully approximate. This is the clearest case for ML necessity. |

**Overall pattern:** the two threats with large-magnitude, fast, structurally simple signals (DDoS, reconnaissance) are where rules alone go furthest. The two threats whose core signal is inherently a *sequence/shape* pattern (C2 beaconing's timing regularity, encrypted-malware's packet-size/timing sequence) are where rules are weakest and ML's value proposition is clearest. DGA, DNS tunnelling, and exfiltration sit in between — rules catch the obvious/unsophisticated cases, but degrade against anything deliberately evasive, which is exactly the comparison this baseline is meant to set up.

---

**No ML models have been selected in this document.** This baseline exists specifically to be beaten (or not) by whatever ML approach is chosen next — establishing, threat by threat, exactly where the burden of proof for "ML adds value" is highest.

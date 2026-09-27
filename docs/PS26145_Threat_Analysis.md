# PS26145 — Threat-Detection Problem Analysis
**Scope:** Passive-observation behavior analysis only. No dataset schemas, feature engineering, or model architecture decisions are made here — that is deferred to a later task, per agreed Source of Truth.

All analysis below respects the OFFICIAL constraints already established: read-only ingest, no return path, no active probing, no handshake initiation, no inline mitigation, no TLS/QUIC payload decryption, streaming/bounded-latency detection.

---

## 1. Volumetric / Protocol DDoS (SYN floods, UDP reflection/amplification, spoofed-source floods)

**Observable passive behavior:**
A sharp, sustained spike in packet/flow rate toward one or a small set of destination IPs/ports, often from a large or spoofed set of source IPs. SYN floods show many half-open-looking flows (SYN seen, no completing ACK visible in the mirrored traffic). UDP amplification shows disproportionately large response sizes relative to small requests, or one destination receiving from an implausibly broad/spoofed source spread.

**Information available:** Packet/flow headers, timestamps, IP/port pairs, protocol, packet/byte counts, TCP flags (SYN/ACK/RST presence as observed passively), source-IP diversity per time window.

**Information unavailable:** True liveness of source IPs (can't verify via probing whether a source is spoofed), server-side response confirmation, any content/payload semantics.

**Required packet/flow metadata:** 5-tuple (src IP, dst IP, src port, dst port, protocol), timestamp, packet count, byte count, TCP flag counts (SYN/ACK/RST) per flow/window, per-destination aggregate rate.

**Detection timescale/window:** Short — sub-second to a few seconds for rate spikes; a rolling short window (e.g., seconds-scale) is appropriate since floods are high-volume and fast-onset.

**Likely false positives:** Legitimate traffic bursts (flash-crowd events, CDN/load-balancer health-check storms, backup jobs, large legitimate broadcast/multicast use, misconfigured retry logic in benign apps).

**Useful SOC evidence:** Packets/sec and bytes/sec time series for the target, source-IP entropy or unique-source count, ratio of SYNs to completed-looking flows, top contributing source IPs/subnets.

**Rules vs ML vs both:** **Both.** Simple rate-threshold rules give a fast, cheap, explainable baseline (and are explicitly called for as the PS's own baseline comparator). ML adds value distinguishing flash-crowd-like benign spikes from adversarial patterns and handling multi-signal combinations (rate + entropy + flag ratios) more robustly than a single threshold.

---

## 2. Botnet C2 Beaconing

**Observable passive behavior:** A host repeatedly contacting the same (or small set of) external destination(s) at regular or near-regular time intervals, often with small, similar-sized payload envelopes, over an extended period (hours to days), regardless of user activity.

**Information available:** Flow timestamps and inter-arrival times, destination IP/domain (if resolvable from associated DNS flows), flow duration, byte counts per beacon, jitter pattern.

**Information unavailable:** Actual C2 command content (encrypted/opaque), attacker infrastructure ownership, confirmation that the destination is malicious (no reputation lookup implied by the PS itself, though external threat-intel feeds could be a design addition — noted, not decided here).

**Required packet/flow metadata:** Per-flow timestamps (for inter-arrival delta calculation), source/destination IP, destination port, flow byte/packet size, session duration, repeat-count toward the same destination over an observation window.

**Detection timescale/window:** Long — needs a sliding window on the order of many minutes to hours (potentially days) to establish periodicity confidently; this is explicitly slower than the DDoS timescale.

**Likely false positives:** Legitimate periodic traffic — NTP sync, telemetry/heartbeat agents, software update checkers, monitoring/health-check pings, scheduled backup or sync jobs. This is explicitly flagged as a known false-positive risk.

**Useful SOC evidence:** Inter-arrival time histogram/variance (periodicity score), destination fan-in (how few destinations are contacted repeatedly), beacon duration consistency, timeline of beacon events.

**Rules vs ML vs both:** **Both**, leaning ML for periodicity scoring (statistical periodicity/regularity metrics are naturally continuous rather than a clean threshold), with rule-based allow-listing for known-benign periodic services (NTP, OS telemetry) to suppress predictable false positives.

---

## 3. DGA Domains

**Observable passive behavior:** DNS queries to domain names with high lexical randomness (algorithmically generated), often with unusual length, character distribution, or a burst of NXDOMAIN responses as malware tries many candidate domains before one resolves.

**Information available:** DNS query name (visible in DNS traffic metadata, not decryption — DNS is typically not encrypted unless DoH/DoT is used, which itself is a signal), query type, response code (NXDOMAIN vs. resolved), query timing, requesting host.

**Information unavailable:** The domain-generation algorithm/seed itself; ground truth on whether a resolved domain is truly malicious without external threat-intel correlation.

**Required packet/flow metadata:** DNS query name string, query type (A/AAAA/TXT/etc.), response code, timestamp, source host, per-host query rate/volume.

**Detection timescale/window:** Short-to-medium — entropy/n-gram scoring can be done per-query (near-instant), but confirming a DGA *campaign* (many failed lookups from one host) benefits from a short rolling window (minutes).

**Likely false positives:** Legitimately random-looking subdomains from CDNs, cloud load-balancers, or A/B-testing infrastructure (e.g., auto-generated subdomains for content delivery), and legitimate short-lived marketing/campaign domains.

**Useful SOC evidence:** Domain-name entropy score, n-gram likelihood score against natural-language models, NXDOMAIN ratio for the requesting host, query volume/burst pattern.

**Rules vs ML vs both:** **Both**, though ML (entropy/n-gram statistical models, or lightweight classifiers over string features) is the natural fit since "looks random" is inherently a scored/statistical judgment rather than a clean rule; simple entropy-threshold rules can serve as a fast pre-filter.

---

## 4. DNS Tunnelling

**Observable passive behavior:** Abnormally large or frequent DNS queries/responses (tunnelling encodes data in query subdomains or TXT/NULL records), unusually long query names, high query rate to a single unusual domain, non-standard record types used unusually often.

**Information available:** DNS query name, length, record type, response size, per-host DNS query rate and volume, requested domain diversity.

**Information unavailable:** Decoded tunnelled payload content/meaning (would require reversing an unknown encoding — out of scope; PS explicitly forbids inferring from decrypted/decoded payload semantics beyond metadata-level anomaly detection).

**Required packet/flow metadata:** DNS query/response size, query name length, record type distribution, query frequency per host, per-domain query concentration.

**Detection timescale/window:** Short-to-medium — abnormal query-length/rate patterns can often be flagged per-query or over a short rolling window (seconds to minutes) since tunnelling tends to be a sustained, higher-frequency channel.

**Likely false positives:** Legitimate services using TXT records extensively (SPF/DKIM lookups, some CDN/cloud config discovery mechanisms), verbose but benign long subdomains from legitimate multi-tenant SaaS platforms.

**Useful SOC evidence:** Query-length distribution vs. baseline, record-type anomaly flags (e.g., high TXT/NULL usage), per-host DNS byte-volume-over-time, single-domain query concentration.

**Rules vs ML vs both:** **Both** — length/record-type threshold rules catch obvious cases cheaply; ML helps generalize across encoding variants and reduces false positives from legitimate verbose DNS usage by learning normal baseline distributions.

---

## 5. Malware Inside Encrypted Sessions (TLS/QUIC metadata only)

**Observable passive behavior:** TLS/QUIC handshake metadata (client/server hello characteristics) that fingerprints to known-malicious or atypical client software, combined with unusual packet-size/timing sequences within the encrypted session that deviate from typical benign application behavior (e.g., a browser-like TLS fingerprint but bot-like traffic timing).

**Information available:** JA3/JA3S/JA4 fingerprints (derived from unencrypted parts of the TLS/QUIC handshake), certificate metadata (if visible, e.g., SNI, cert validity fields), packet-size sequences, inter-packet timing within the session, session duration.

**Information unavailable:** Any decrypted application payload — this is an explicit, non-negotiable constraint. No inspection of actual data exchanged inside the encrypted channel is possible or permitted.

**Required packet/flow metadata:** JA3/JA3S/JA4 fingerprint hash, SNI (if present/unencrypted), packet-size sequence per session, inter-arrival timing sequence, session duration, TLS/QUIC version.

**Detection timescale/window:** Medium — needs the handshake plus enough of the subsequent packet sequence to build a meaningful size/timing signature; likely a per-session window rather than a fixed time-slice.

**Likely false positives:** Legitimate applications that happen to share a fingerprint with known malware families (fingerprint collisions are a known, documented weakness of JA3-style techniques), or unusual-but-benign traffic shaping from certain legitimate low-bandwidth or automated clients (IoT devices, scripts, monitoring agents).

**Useful SOC evidence:** The specific fingerprint hash and any known association, packet-size/timing sequence visualization, SNI (if visible) for context, deviation score from expected benign session profile.

**Rules vs ML vs both:** **Both** — fingerprint blocklist/allowlist matching is rule-based and fast; ML is needed for the size/timing sequence analysis since "does this encrypted session's shape resemble malware C2 vs. benign app" is a pattern-recognition problem, not a clean rule. This category is explicitly noted as vulnerable to evasion (malware mimicking benign JA3 fingerprints).

---

## 6. Reconnaissance / Port Scanning

**Observable passive behavior:** A single source IP contacting many distinct destination ports on one host (vertical scan) and/or many distinct destination hosts on one or few ports (horizontal scan) within a short time window, typically with short-lived or incomplete-looking flows.

**Information available:** Source IP, set of destination IPs/ports contacted, timing between attempts, flow completion status (as passively observable via flags), per-source fan-out counts.

**Information unavailable:** Attacker intent/tooling identity beyond the pattern itself; whether a "closed port" response was actually returned (no ability to correlate response side beyond what's passively mirrored, and no active follow-up allowed).

**Required packet/flow metadata:** Source IP, destination IP, destination port, timestamp, per-source unique-destination-port count and unique-destination-host count over a window, flag state per flow.

**Detection timescale/window:** Short — scanning behavior is a rate/fan-out phenomenon best captured in a short rolling window (seconds to a couple of minutes), similar timescale to DDoS detection.

**Likely false positives:** Legitimate network/vulnerability scanners run by the organization itself, load balancers or service-discovery mechanisms probing multiple backend ports/hosts, misconfigured clients retrying across a port range.

**Useful SOC evidence:** Fan-out count (unique ports/hosts touched by the source), scan rate over time, list of targeted ports/hosts, flow-completion ratio (mostly incomplete = more scan-like).

**Rules vs ML vs both:** **Both** — fan-out threshold rules are simple, fast, and reasonably effective (a classic, well-understood detection pattern); ML adds value in tuning sensitivity/reducing false positives from legitimate internal scanning tools and correlating scan bursts with subsequent activity (recon → exploit chains).

---

## 7. Data Exfiltration

**Observable passive behavior:** A host or flow showing markedly asymmetric traffic volume — much more data flowing outbound than would be expected for the apparent protocol/session type — or an unusual outbound:inbound byte ratio sustained over a session or across many sessions from the same source, especially toward unfamiliar or newly-seen external destinations.

**Information available:** Per-flow/per-host outbound and inbound byte counts, session duration, destination novelty (first-seen vs. established destination), protocol/port used for the transfer.

**Information unavailable:** The actual content being exfiltrated (payload, if encrypted, is off-limits by constraint; even if unencrypted, the PS's detection basis is explicitly volume/ratio-based, not content inspection), true intent (business-legitimate large upload vs. malicious).

**Required packet/flow metadata:** Outbound byte count, inbound byte count, byte-ratio per flow/session, destination IP/port, timestamp, destination novelty flag, cumulative per-host outbound volume over a window.

**Detection timescale/window:** Medium — meaningful ratio/volume anomalies often need aggregation over a session or a rolling window of minutes-to-hours to distinguish a genuine large-but-legitimate transfer from a suspicious pattern, though a single very large sudden transfer could also be flagged near-immediately.

**Likely false positives:** Legitimate large uploads (backups, cloud sync, video/content uploads, software deployment pushes), asymmetric-by-design protocols (e.g., streaming ingest, telemetry uploads).

**Useful SOC evidence:** Outbound:inbound byte ratio, absolute outbound volume, destination novelty/reputation context, historical baseline comparison for that host.

**Rules vs ML vs both:** **Both** — simple ratio/volume threshold rules provide an interpretable first pass; ML helps by learning per-host/per-service "normal" baselines so that genuinely unusual transfers are flagged relative to context rather than a single global threshold (which would otherwise generate heavy false positives against legitimately bursty organizations).

---

## THREAT → OBSERVABLE SIGNAL → DETECTION APPROACH

| Threat | Observable Signal | Detection Approach |
|---|---|---|
| SYN/UDP/spoofed-source DDoS | Sudden high-rate packet/flow spike toward a target, high source-IP diversity/entropy, elevated SYN-without-completion ratio | Rules (rate thresholds) + ML (entropy/flag-pattern anomaly scoring) |
| C2 Beaconing | Regular, low-jitter inter-arrival timing from a host to a small, fixed destination set over a long window | ML (periodicity/regularity scoring) + rule-based allow-listing for known-benign periodic services |
| DGA Domains | High-entropy/unnatural n-gram domain names, elevated NXDOMAIN rate from a host | ML (entropy/n-gram statistical scoring) + rule pre-filter |
| DNS Tunnelling | Abnormally long/frequent DNS queries, atypical record-type usage (TXT/NULL), high per-domain query concentration | Rules (length/record-type thresholds) + ML (baseline deviation modeling) |
| Encrypted-Session Malware (TLS/QUIC metadata) | Known/atypical JA3-JA3S-JA4 fingerprint combined with anomalous packet-size/timing sequence in the session | Rules (fingerprint blocklist/allowlist) + ML (sequence-pattern anomaly detection) |
| Reconnaissance / Port Scanning | Single source fanning out across many destination ports/hosts in a short window, mostly incomplete flows | Rules (fan-out count thresholds) + ML (sensitivity tuning, recon-to-exploit correlation) |
| Data Exfiltration | Asymmetric outbound:inbound byte ratio or unusually large outbound volume, especially to novel destinations | Rules (ratio/volume thresholds) + ML (per-host/service baseline deviation modeling) |

---

**No dataset schemas, feature engineering pipelines, or model architectures have been defined in this document** — this is behavior-level threat analysis only, per the agreed task scope.

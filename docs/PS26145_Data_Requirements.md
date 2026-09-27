# PS26145 — Data Requirements Analysis
**Scope:** What raw data each detector needs, at the field level. No dataset selection, no feature engineering, no model design. Builds directly on the agreed threat decomposition — not re-analyzing behavior here.

Constraint check applied to every field below: must be obtainable from passive, unidirectional, read-only observation, without decryption, probing, or handshake initiation.

---

## 1. SYN/UDP/Spoofed-Source DDoS

- **Raw packet fields:** TCP flags (SYN, ACK, RST) per packet, IP TTL (spoofing can produce TTL inconsistencies), packet length, protocol number.
- **Flow fields:** 5-tuple (src IP, dst IP, src port, dst port, protocol), packet count, byte count, flow start/end time.
- **DNS metadata:** Not applicable to this threat.
- **TLS/QUIC metadata:** Not applicable to this threat.
- **Timing information:** Packet arrival timestamps (for rate-per-second computation), flow duration.
- **Directional information:** Direction of flow (inbound to target vs. outbound), needed to compute rate *toward* a destination and distinguish request vs. response volume in amplification cases.
- **Labels:** Benign / DDoS (binary or multi-class member of the 7-class label set), ideally sub-typed (SYN flood / UDP amplification / spoofed flood) if the generation tool records which attack was run.
- **Temporal context:** Short rolling window state (recent per-destination rate, recent per-source count) — i.e., the detector needs access to a short history buffer, not just the current packet.

---

## 2. Botnet C2 Beaconing

- **Raw packet fields:** Packet length (beacon payload envelope size), protocol.
- **Flow fields:** 5-tuple, byte/packet count per flow, flow duration, repeat count of flows between the same src/dst pair.
- **DNS metadata:** Destination domain name (if the C2 destination is resolved via DNS observable in the same passive feed) — links a beacon's IP back to a domain for evidence/context.
- **TLS/QUIC metadata:** JA3/JA3S/JA4 fingerprint if beacon is over TLS (useful corroborating signal, not this threat's primary basis).
- **Timing information:** Precise per-flow timestamps to same destination, needed to compute inter-arrival deltas and jitter/variance over a long history.
- **Directional information:** Outbound direction (host → external destination) is the relevant direction; inbound response size may also matter (typically small, consistent with C2 polling).
- **Labels:** Benign / C2 beaconing, with ground truth needing to record which flows belong to the sandboxed C2 emulator's traffic.
- **Temporal context:** Long history buffer per src/dst pair (many minutes to hours/days) to establish periodicity — this detector's temporal context requirement is qualitatively larger than DDoS/scanning.

---

## 3. DGA Domains

- **Raw packet fields:** Not directly needed beyond what carries the DNS message (UDP/TCP port 53 or DoH/DoT port context).
- **Flow fields:** Source host identifier, per-host DNS query count/rate over a window.
- **DNS metadata:** Query name (string), query type, response code (NXDOMAIN vs. resolved), query/response timestamp — this threat's detection is almost entirely DNS-metadata-driven.
- **TLS/QUIC metadata:** Not applicable, unless DoH is in use, in which case the DNS query itself becomes invisible except as generic TLS metadata (an important limitation, noted below).
- **Timing information:** Per-query timestamp, inter-query timing from the same host (burst detection).
- **Directional information:** Query direction (host → resolver) vs. response direction; largely a formality here since DNS is inherently request/response.
- **Labels:** Benign / DGA, ideally with the specific DGA family or generation algorithm recorded if generated from published algorithms/DGArchive.
- **Temporal context:** Short-to-medium window per host (minutes) to compute NXDOMAIN ratio and query burst rate.

---

## 4. DNS Tunnelling

- **Raw packet fields:** Not directly needed beyond DNS message framing.
- **Flow fields:** Per-host DNS byte volume over time, per-domain flow/query concentration.
- **DNS metadata:** Query name length, record type (A/AAAA/TXT/NULL/etc.), response size, query frequency per host, per-domain query count — again, primarily DNS-metadata-driven.
- **TLS/QUIC metadata:** Not applicable (same DoH caveat as DGA above).
- **Timing information:** Query timestamps, inter-query timing to the same domain (sustained-channel detection).
- **Directional information:** Query vs. response direction; response size direction matters since tunnelling can encode data in either query subdomains or response records.
- **Labels:** Benign / DNS tunnelling, tool-tagged (dnscat2 vs. iodine) if the generator records it.
- **Temporal context:** Short-to-medium window per host/domain pair to detect sustained abnormal query volume/length.

---

## 5. Malware Inside Encrypted Sessions (TLS/QUIC metadata only)

- **Raw packet fields:** Packet length sequence within the session (size of each packet in order), inter-packet arrival times.
- **Flow fields:** 5-tuple, session duration, total byte/packet counts.
- **DNS metadata:** SNI-linked domain if a preceding DNS query resolved the destination (contextual evidence, not primary basis).
- **TLS/QUIC metadata:** JA3 (TLS client fingerprint), JA3S (TLS server fingerprint), JA4 (newer fingerprint standard), SNI field (often unencrypted in TLS ClientHello, though ECH can hide it — a real availability caveat), TLS/QUIC version, cipher suite list from the handshake.
- **Timing information:** Inter-packet timing sequence for the session (used with packet-size sequence to build the behavioral fingerprint).
- **Directional information:** Client→server vs. server→client packet sequences are typically analyzed separately since their size/timing patterns differ.
- **Labels:** Benign / encrypted-session malware, with the malware family or emulation tool recorded if known.
- **Temporal context:** Per-session context only (this detector operates at the session level, not a rolling multi-session window) — though a per-fingerprint historical reputation could be a design addition, not decided here.

---

## 6. Reconnaissance / Port Scanning

- **Raw packet fields:** TCP flags (to assess flow completion state), packet length (scans are often minimal-payload).
- **Flow fields:** Source IP, destination IP, destination port, per-source unique-destination-port count, per-source unique-destination-host count over a window, flow completion status.
- **DNS metadata:** Not applicable.
- **TLS/QUIC metadata:** Not applicable.
- **Timing information:** Timestamp of each connection attempt (needed to compute scan rate and fan-out speed).
- **Directional information:** Outbound-from-scanner direction is the relevant one; inbound response (if visible in the mirrored data) helps assess flow completion but per the PS's passive/no-return-path framing, the monitor may only see the scanning side of traffic depending on mirror placement — this is an availability caveat, not a design decision.
- **Labels:** Benign / reconnaissance, ideally sub-typed (vertical vs. horizontal scan) if the generator differentiates.
- **Temporal context:** Short rolling window per source IP (seconds to a couple of minutes) to accumulate fan-out counts.

---

## 7. Data Exfiltration

- **Raw packet fields:** Packet length (contributes to volume aggregation), not otherwise distinct.
- **Flow fields:** Outbound byte count, inbound byte count, byte ratio, destination IP/port, per-host cumulative outbound volume over a window, destination novelty flag (first-seen vs. established).
- **DNS metadata:** Domain associated with the destination (context/evidence), not primary detection basis.
- **TLS/QUIC metadata:** Not primary basis, though session duration/volume from TLS flow metadata still applies.
- **Timing information:** Session/flow start-end timestamps; timing of when a host's outbound volume crosses an unusual threshold.
- **Directional information:** This threat's detection is *fundamentally* directional — outbound vs. inbound byte volume comparison is the core signal.
- **Labels:** Benign / data exfiltration, tagged with which mechanism generated it if simulated (e.g., large upload emulation).
- **Temporal context:** Medium window (session-level up to multi-hour aggregation per host) to distinguish sustained anomalous transfer from a one-off legitimate large upload.

---

## THREAT → REQUIRED DATA → PURPOSE

| Threat | Required Data | Purpose |
|---|---|---|
| DDoS (SYN/UDP/spoofed) | TCP flags, TTL, 5-tuple, packet/byte counts, per-destination rate, arrival timestamps, flow direction | Detect abnormal volumetric spikes and incomplete-handshake ratios toward a target |
| C2 Beaconing | 5-tuple, flow byte/packet size, repeat-flow timestamps to same destination, resolved domain (if available), outbound direction | Detect regular, low-jitter contact with a small fixed destination set over long time horizons |
| DGA Domains | DNS query name, query type, response code, per-host query timing/rate | Detect algorithmically-generated, high-entropy domain lookups and NXDOMAIN bursts |
| DNS Tunnelling | DNS query length, record type, response size, per-host/domain query volume and timing | Detect abnormal DNS channel usage consistent with data encoding in queries/responses |
| Encrypted-Session Malware | JA3/JA3S/JA4, SNI (if visible), packet-size sequence, inter-packet timing, session duration | Fingerprint and behaviorally profile encrypted sessions without decrypting payload |
| Reconnaissance/Scanning | Source IP, destination IP/port, per-source fan-out counts, TCP flags, attempt timestamps | Detect single-source fan-out across many ports/hosts in a short window |
| Data Exfiltration | Outbound/inbound byte counts, byte ratio, destination novelty, per-host cumulative volume, timestamps | Detect asymmetric or unusually large outbound transfers relative to baseline |

---

## Fields Common to All Detectors

- Source IP, destination IP (or their derived/anonymized equivalents)
- Timestamp (packet or flow-level)
- Protocol identifier
- Some notion of flow/session grouping (5-tuple or equivalent) to associate observations belonging to the same conversation
- A label field (ground truth for training/evaluation, since all seven are supervised-classification candidates per the earlier requirement analysis)
- Access to recent temporal context (a rolling buffer/window state per relevant key — host, destination, or flow), since every detector operates over some window rather than a single isolated packet

## Threat-Specific Fields

| Threat | Fields unique to it (not needed by most others) |
|---|---|
| DDoS | TCP flag ratios, TTL, source-IP diversity/entropy per destination |
| C2 Beaconing | Long-horizon inter-arrival variance/jitter, repeat-destination count over long windows |
| DGA | DNS query-name string content, NXDOMAIN response code |
| DNS Tunnelling | DNS record type, query-name length, response size |
| Encrypted-Session Malware | JA3/JA3S/JA4 fingerprint hashes, packet-size/timing sequence within a session, TLS/QUIC version |
| Reconnaissance/Scanning | Per-source unique-port and unique-host fan-out counts, flow-completion state |
| Data Exfiltration | Outbound:inbound byte ratio, destination novelty/first-seen flag |

## Fields Unavailable Under the Passive Constraint

- Any confirmation of true source-IP liveness/ownership (can't verify by probing — relevant to spoofed-source DDoS)
- Server-side/destination-side confirmation of connection outcome when the mirror only captures one direction of a link (relevant to scan-completion assessment)
- Decrypted payload content of any kind (relevant to encrypted-session malware, DNS-tunnelling payload decoding, and general content-based exfiltration detection)
- DNS query visibility when DoH/DoT is used — the DNS message itself becomes opaque, visible only as generic encrypted TLS metadata (relevant to DGA and DNS tunnelling detectors specifically)
- SNI field when Encrypted Client Hello (ECH) is used — removes a currently-assumed-available piece of TLS metadata
- External threat-intelligence/reputation context (domain reputation, IP reputation, known-bad fingerprint databases) — not inherently unavailable by the passive constraint itself, but not present in the "required inputs" defined by the official PS scope, so its availability is an open question, not a given
- Any live/interactive response from the destination confirming exfiltration success or C2 command content

## Fields That Must Never Be Used (Would Violate the PS)

- Decrypted TLS/QUIC payload content, under any circumstance — explicit, non-negotiable OFFICIAL constraint
- Any field or signal that could only be obtained by the detector actively sending a packet, probe, or query (e.g., an active DNS resolution check, an active port probe to verify scan targets, an active handshake completion) — violates read-only/no-return-path/no-active-probing constraints
- Any field implying the system pushed a command back across the ingest path (e.g., simulated "verify by reconnecting" logic) — violates no-inline-mitigation/no-return-path constraint
- Any field requiring bidirectional live correlation the mirror architecture cannot provide (e.g., assuming the detector can query the source host directly for context) — violates the fundamental unidirectional-observation premise

---

**No dataset selection or feature engineering has been performed in this document** — this is a raw-data-requirements inventory only, per the agreed task scope.

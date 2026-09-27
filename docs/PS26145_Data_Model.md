# PS26145 — Canonical Internal Data Model
**Scope:** Define the normalized internal representation that PCAP, NetFlow, IPFIX, sFlow, and derived flow records all map into. Field-level schema only — no derived ML features (no entropy, n-grams, periodicity scores, ratios, etc. are defined here; those are a later, explicitly deferred task).

---

## 0. Design Rationale

Three separate structures, linked rather than merged into one flat record:

- **FlowRecord** — the core, always-present structure every input format can populate at some level. Every one of the seven threats needs *some* subset of FlowRecord.
- **DNSRecord** — DNS is transactional (query/response pairs), not flow-shaped in the same sense, and only a minority of flows carry DNS content. Embedding DNS fields directly into every FlowRecord would leave them null for ~all non-DNS traffic. Kept as a separate structure, linked back to its parent flow.
- **TLSQUICMetadata** — likewise only populated for TLS/QUIC sessions, and structurally different (handshake-derived fingerprints, session-level sequences) from generic flow fields. Kept separate, linked back to its parent flow.

This mirrors how real exporters work too: a NetFlow/IPFIX collector normally emits generic flow fields regardless of payload, while DNS- or TLS-aware enrichment (via DPI-lite parsing at the capture stage) is a separate, optional enrichment step layered on top — not something every input format can supply.

**Relationship:** One `FlowRecord` has zero-or-one linked `DNSRecord` (or, for busy resolvers, a flow may represent many DNS transactions — see §3 note) and zero-or-one linked `TLSQUICMetadata` record, joined via `flow_id`.

---

## 1. FlowRecord

### 1.1 Identifiers

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `flow_id` | string (hash of 5-tuple + start_time, or exporter-native if present) | Derived — always computed if not natively provided; PCAP/NetFlow/IPFIX/sFlow/derived flows all get one assigned at normalization time | Required | Unique identifier for this flow record, used as the official alert-schema's flow identifier | All (required by official alert schema) |
| `label` | string/enum (`benign`, one of 7 threat classes) | Ground-truth logger (lab/training context only) | Optional — present only in training/eval data, absent/null in a live production flow | Ground-truth class for this flow, for training and evaluation | None directly — used for training/evaluation, not by the detectors at inference time |
| `experiment_id` | string | Ground-truth logger (lab context only) | Optional | Traceability back to the generating lab experiment | None — dataset provenance only |

### 1.2 Temporal

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `start_time` | timestamp, UTC, millisecond (or finer) precision | PCAP (first packet), NetFlow/IPFIX (flow-start field), sFlow (sample time, coarser), derived flow tools (native) | Required | Time the flow was first observed | All |
| `end_time` | timestamp, UTC | Same as above (flow-end field); for an in-progress flow in a streaming context, this is updated/absent until flow close | Required for a closed flow; optional/null while the flow is still active | Time of the last packet in the flow (or last-updated time for active flows) | DDoS, exfiltration, C2 (duration-dependent) |
| `duration` | float, seconds | Derived (`end_time − start_time`) if not natively present | Optional (computable) | Total flow lifetime | C2 beaconing (session duration), DDoS |

### 1.3 Addressing

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `src_ip` | string (IPv4 or IPv6) | PCAP/NetFlow/IPFIX/sFlow/derived — universal | Required | Source address of the flow | All |
| `dst_ip` | string (IPv4 or IPv6) | Same | Required | Destination address | All |
| `src_port` | uint16 | Same, where the protocol has ports | Optional (null for protocols without ports, e.g. ICMP) | Source port | DDoS, reconnaissance |
| `dst_port` | uint16 | Same | Optional (null for portless protocols) | Destination port | Reconnaissance, DDoS |
| `protocol` | enum / uint8 (IANA protocol number: TCP=6, UDP=17, ICMP=1, etc.) | Universal | Required | Layer-4 protocol | DDoS, reconnaissance |

### 1.4 Protocol / Flags

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `tcp_flags_cumulative` | bitfield/list of flags seen (SYN, ACK, RST, FIN, PSH, URG) | NetFlow v5/v9 and IPFIX natively export a cumulative OR of flags seen across the flow; PCAP and derived flow tools can compute this same summary | Optional (TCP only; null for UDP/ICMP) | Which TCP flags appeared anywhere in the flow — a coarse completion signal | DDoS (SYN-without-completion ratio), reconnaissance (flow-completion state) |
| `tcp_flags_sequence` | ordered list of per-packet flag sets | PCAP only | Optional (finer-grained; not available from NetFlow/IPFIX/sFlow) | Per-packet flag progression within the flow | DDoS, reconnaissance — when PCAP-level granularity is available |

### 1.5 Volume

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `packet_count` | uint64 | Universal (sFlow value is an extrapolation from sampled packets, not an exact count — see §6 caveat) | Required | Total packets observed in the flow | DDoS, reconnaissance, exfiltration |
| `byte_count` | uint64 | Universal (same sFlow sampling caveat) | Required | Total bytes observed in the flow | DDoS, exfiltration |
| `fwd_packet_count` / `bwd_packet_count` | uint64 | PCAP, bidirectional-capable exporters (IPFIX with biflow support, Argus-style tools, some NetFlow v9 templates); requires the exporter or normalization layer to correlate the two unidirectional halves of a conversation | Optional — depends on whether the source format is bidirectional-aware (see §6) | Packet counts split by direction relative to the flow's initiator | Exfiltration (asymmetry), encrypted-session malware (sequence shape) |
| `fwd_byte_count` / `bwd_byte_count` | uint64 | Same as above | Optional, same dependency | Byte counts split by direction | Exfiltration (outbound:inbound ratio) — this threat's core signal |

### 1.6 Direction

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `direction` | enum (`outbound`, `inbound`, `internal`, `unknown`) | Derived — requires the normalization layer to know which IP ranges are "inside" the monitored boundary vs. external; not natively present in any raw exporter format | Optional at ingestion, but effectively required before this field is usable — **the internal/external subnet definition itself is an open configuration decision, not resolved by this schema** | Which side of the monitored boundary each address falls on | Exfiltration (defines "outbound"), DDoS (defines "toward target") |
| `is_bidirectional_source` | boolean | Derived from which exporter produced the record (NetFlow v5/sFlow are natively unidirectional; IPFIX-biflow/Argus-style/derived tools may be natively bidirectional) | Required (internal bookkeeping field, not a detector input) | Flags whether `fwd_*`/`bwd_*` fields came directly from the exporter or had to be derived by pairing two unidirectional records | None — pipeline/normalization metadata only |

### 1.7 Raw Packet-Level Sequences (session-scoped, not yet summarized/derived)

These are **raw observed sequences**, not engineered statistics — no mean/variance/entropy is computed here; that is explicitly deferred to feature engineering.

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `packet_timestamps` | ordered list of timestamps | PCAP only | Optional — unavailable from NetFlow/IPFIX/sFlow, which report flow-level summaries, not per-packet timing | Arrival time of every packet in the session, in order | C2 beaconing (inter-arrival pattern), encrypted-session malware (timing sequence) |
| `packet_sizes` | ordered list of integers (bytes) | PCAP only (some IPFIX exporters can optionally export limited packet-size distributions, but not a full ordered sequence) | Optional, same availability caveat | Size of every packet in the session, in order | Encrypted-session malware (packet-size sequence signature) |

---

## 2. DNSRecord

Linked to a parent `FlowRecord` via `flow_id` (the flow carrying the DNS conversation on port 53, or the relevant DoH/DoT flow if encrypted — see the transport-visibility caveat below).

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `dns_transaction_id` | string/uint16 (DNS header transaction ID) | PCAP, or a derived flow tool with DNS-aware parsing enabled | Required | Correlates a query with its corresponding response | DGA domains, DNS tunnelling |
| `flow_id` | string | Derived — links back to the parent FlowRecord | Required | Association to the carrying flow | All DNS-based detectors |
| `timestamp` | timestamp, UTC | Same as flow source | Required | When this query or response was observed | DGA, DNS tunnelling |
| `query_name` | string | PCAP / DNS-aware parsing only — plain NetFlow/IPFIX/sFlow do not expose this without DPI-lite enrichment | Required for query records | The domain name being queried | DGA (lexical analysis), DNS tunnelling (length analysis) |
| `query_type` | enum (A, AAAA, TXT, NULL, MX, CNAME, etc.) | Same as `query_name` | Required for query records | Requested DNS record type | DNS tunnelling (atypical record-type usage) |
| `response_code` | enum (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, etc.) | Same, only present once a response is observed | Optional — null until/unless a response is captured | Resolution outcome | DGA (NXDOMAIN-burst detection) |
| `response_size` | uint32 (bytes) | Same | Optional, response-only | Size of the DNS response message | DNS tunnelling (abnormal response size) |
| `query_length` | uint16 | Derived from `query_name` (simple length count, not a statistical feature) | Optional (trivially computable) | Character length of the queried name | DNS tunnelling |
| `src_ip` | string | Same as flow source | Required | Host that issued the query | DGA, DNS tunnelling |
| `dst_ip` | string | Same | Required | Resolver contacted | DGA, DNS tunnelling |
| `transport` | enum (`udp53`, `tcp53`, `doh`, `dot`) | Derived — inferred from port number and, for encrypted variants, from TLS/QUIC wrapper detection | Required | Which DNS transport carried this record | DGA, DNS tunnelling — **critically, this field is what flags the DoH/DoT blind spot identified earlier**: when `transport` is `doh`/`dot`, the `query_name`/`query_type`/`response_code` fields above will typically be unavailable (the message itself is encrypted), and only generic TLS/QUIC metadata remains observable for that traffic |

**Note on flow/record cardinality:** a single long-lived flow to a busy resolver could in principle carry many DNS transactions; in that case DNSRecord is genuinely one-to-many against its parent FlowRecord (each query/response pair gets its own DNSRecord, all sharing the same `flow_id`), rather than DNS fields being folded into the flow itself.

---

## 3. TLSQUICMetadata

Linked to a parent `FlowRecord` via `flow_id`. Populated only for TLS/QUIC sessions where handshake metadata was observed.

| Field | Type | Source | Required/Optional | Meaning | Detectors using it |
|---|---|---|---|---|---|
| `flow_id` | string | Derived — links back to parent FlowRecord | Required | Association to the carrying flow | Encrypted-session malware |
| `ja3` | string (MD5 hash) | PCAP only — computed from the TLS ClientHello; not exposed by plain NetFlow/IPFIX/sFlow without DPI-lite enrichment | Optional — null if ClientHello wasn't visible (e.g., ECH in use) | Client-side TLS fingerprint | Encrypted-session malware (primary signal) |
| `ja3s` | string (MD5 hash) | PCAP only, from the ServerHello | Optional | Server-side TLS fingerprint | Encrypted-session malware |
| `ja4` | string | PCAP only, requires JA4-capable parsing | Optional (newer standard; tooling support varies) | Alternative/updated client fingerprint, addressing some known JA3 weaknesses | Encrypted-session malware |
| `sni` | string | PCAP, from the ClientHello's SNI extension (plaintext in classic TLS; hidden if Encrypted Client Hello, ECH, is used) | Optional — a known availability caveat, not guaranteed | Requested server hostname | Encrypted-session malware (contextual evidence), C2 beaconing (domain linkage) |
| `tls_version` / `quic_version` | enum | PCAP, from the handshake | Optional | Negotiated protocol version | Encrypted-session malware |
| `cipher_suites_offered` | ordered list | PCAP, from ClientHello (this list is itself one of the JA3 hash's inputs, kept here as the raw pre-hash value) | Optional | Cipher suites the client offered | Encrypted-session malware (contributes to fingerprint) |
| `cert_issuer` / `cert_valid_from` / `cert_valid_to` | string / timestamp / timestamp | PCAP, from the handshake certificate exchange (metadata only — not decrypted application payload; certificate exchange itself is part of the unencrypted or lightly-protected handshake in most TLS/QUIC versions) | Optional — secondary/corroborating evidence, not the primary detection basis | Certificate validity window and issuer | Encrypted-session malware (secondary) |
| `session_duration` | float, seconds | Derived from parent FlowRecord's `duration` | Optional (redundant with FlowRecord, convenience field) | Session lifetime | Encrypted-session malware |
| `packet_size_sequence_ref` / `packet_timing_sequence_ref` | reference to parent FlowRecord's `packet_sizes` / `packet_timestamps` | Derived — pointer, not a duplicate copy | Optional | Links this session's fingerprint to its raw packet-size/timing sequence | Encrypted-session malware (core signal, combined with fingerprint) |

---

## 4. Field Availability by Source Format

This is the gap analysis the PS's own input-format list (PCAP, NetFlow, IPFIX, sFlow, derived flow records) requires — not every format can populate every field above.

| Field Category | PCAP | NetFlow v5 | NetFlow v9 | IPFIX | sFlow | Derived flow tools (Argus/nfstream/CICFlowMeter-style) |
|---|---|---|---|---|---|---|
| 5-tuple, protocol, ports | Yes | Yes | Yes | Yes | Yes (per sampled packet) | Yes |
| Timestamps (flow start/end) | Yes (packet-precise) | Yes (flow-level) | Yes | Yes | Yes (sample-time only, coarser) | Yes |
| Packet/byte counts | Yes (exact) | Yes (exact, exporter-counted) | Yes | Yes | **Estimated** — sFlow is sampled, so counts are statistical extrapolations, not exact | Yes (exact, since built from PCAP or exact flow export) |
| TCP flags (cumulative) | Yes | Yes (has a flags field) | Yes | Yes | Only for sampled packets, not flow-wide | Yes |
| TCP flags (per-packet sequence) | Yes | No | No | No | No | Only if built from PCAP |
| Bidirectional fwd/bwd split | Derivable (by pairing) | No (unidirectional only) | Usually no (template-dependent) | Possible with biflow-capable templates | No | Yes, if the tool is bidirectional-aware (e.g., Argus, nfstream) |
| Packet-size / timing sequences | Yes (only source) | No | No | No (not in standard templates) | No | Only if the tool retains/derives from PCAP |
| DNS metadata (query name, type, response code) | Yes (via DPI-lite parsing) | No | No | Only with vendor/enterprise-specific IPFIX elements, not guaranteed | No | Only if the tool includes DNS-aware parsing |
| TLS/QUIC fingerprints (JA3/JA3S/JA4, SNI) | Yes (via handshake parsing) | No | No | Only with vendor/enterprise-specific elements, not guaranteed | No | Only if the tool includes TLS-aware parsing |

**Implication for the normalization layer:** PCAP is the only universally complete source; NetFlow/IPFIX/sFlow-only deployments will arrive with `null` DNSRecord/TLSQUICMetadata and no raw packet-sequence fields, meaning the encrypted-malware and (partially) the DGA/DNS-tunnelling detectors depend on either PCAP-level capture being available at the mirror point, or a DPI-lite-capable flow exporter being used — this is a real architectural dependency to be explicit about, not something to design around silently.

---

## 5. Cross-Cutting Field Notes

- **Timestamps:** all stored as UTC; precision should be the best the source format offers (PCAP: sub-millisecond typically; flow exporters: usually millisecond or coarser) — no attempt is made here to fabricate precision a source doesn't have. Clock-sync dependency on the lab's internal NTP setup (established in the prior lab-architecture task) is what makes cross-source timestamp comparison meaningful at all.
- **IP addresses:** stored as strings supporting both IPv4 and IPv6; no anonymization/hashing scheme is defined here — whether to anonymize source IPs for storage/privacy is an open team decision, not resolved by this schema.
- **Ports:** nullable, since ICMP and some other protocols carry no port concept — treating a missing port as `0` instead of `null` would be a meaningful-value collision and is avoided.
- **Protocol:** stored as the IANA-assigned protocol number (not a free-text string) to keep it exporter-agnostic and avoid inconsistent naming (`"tcp"` vs `"TCP"` vs `6`) across sources.
- **TCP flags:** deliberately modeled at two levels of granularity (`tcp_flags_cumulative` vs `tcp_flags_sequence`) because the former is what most flow exporters can give, while the latter is a strictly richer PCAP-only signal — collapsing them into one field would silently downgrade PCAP-sourced data to flow-exporter granularity.
- **Packets/bytes:** the sFlow sampling caveat above is important enough to repeat — any detector relying on exact volume counts (DDoS rate thresholds, exfiltration volume) will see noisier, extrapolated numbers from sFlow-only sources than from PCAP/NetFlow/IPFIX.
- **Duration:** always derivable from `start_time`/`end_time`, so it is marked optional/computable rather than a hard requirement on every source format.
- **Direction:** flagged above as depending on an internal/external subnet definition that this schema does not itself supply — that boundary definition is an open configuration/team decision for whatever environment the detector is deployed in (the lab's isolated segment, in the current prototype context).
- **Packet timing/sizes:** kept as raw ordered lists rather than pre-summarized, per the task's instruction not to engineer derived features yet — any statistical summarization of these sequences (mean, variance, entropy, periodicity scoring) is explicitly out of scope for this document.
- **DNS metadata:** modeled as a linked, potentially one-to-many structure rather than embedded fields, both because most flows carry no DNS content and because a single flow can carry multiple DNS transactions.
- **TLS/QUIC fingerprints:** modeled as a linked, optional structure for the same reason, with explicit notation of the ECH/SNI-visibility and JA3-availability caveats already identified as open risks in earlier tasks — this schema does not resolve those risks, only represents them faithfully as nullable fields.

---

**No derived ML features have been defined in this document** — entropy, n-gram scores, periodicity metrics, byte ratios, fan-out counts, and similar statistics are all deferred to a later, explicit feature-engineering task. This document defines only the canonical raw/normalized data shape those features will eventually be computed from.

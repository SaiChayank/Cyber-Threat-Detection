# PS26145 — Feature Engineering System Design
**Scope:** Feature definitions computed from the canonical FlowRecord/DNSRecord/TLSQUICMetadata schema, designed for streaming/online, strictly causal computation. No model architecture or algorithm selection happens in this document — that is deferred.

**Causality rule applied to every feature below:** a feature value for an event at time `t` may only use raw data with timestamp `≤ t`. No feature is permitted to reach into future records, future window contents, or statistics computed over a period that includes data after `t`.

---

## 1. Online Computation Building Blocks (used throughout)

Rather than repeating implementation detail per feature, these are the streaming primitives referenced below:

| Primitive | Purpose | Why it's needed |
|---|---|---|
| **Tumbling/sliding window counters** | Rate, count, and sum features over a fixed recent time span | Bounded-memory, causal-by-construction (window only ever contains past-to-present data) |
| **Welford's incremental mean/variance** | Running mean and variance without storing the full sample history | O(1) memory per key, exact (not approximate), naturally online |
| **Exponentially weighted moving average/variance (EWMA/EWMV)** | Long-horizon "baseline" tracking (e.g., per-host normal volume) where recent data should matter more than old data, without unbounded history | Bounded memory, adapts to drift, appropriate for the long C2/exfiltration windows |
| **HyperLogLog (approximate distinct count)** | Fan-out/fan-in counts over unbounded key spaces (unique source IPs, unique destination hosts, unique domains) | Exact distinct counting over unbounded IDs is memory-unbounded; HLL bounds memory at the cost of small, known error |
| **Exact bitmap/set counting** | Fan-out counts over *bounded* key spaces (e.g., destination ports — only 65,536 possible values) | Where the key space is small and bounded, exact counting is cheap and preferable to an approximate sketch |
| **Count-Min Sketch (approximate frequency)** | Approximating a frequency distribution (e.g., source-IP distribution toward a destination) cheaply, used as the input to streaming entropy estimation | Avoids storing a full per-key histogram for unbounded key spaces |
| **Bloom filter (approximate set membership)** | "Have we seen this destination before?" novelty checks over unbounded destination spaces | Bounded memory; false positives are acceptable (biases toward "seen before," i.e., conservative on the exfiltration-novelty signal) and there are no false negatives |
| **Bounded-length prefix buffers** | Packet-size/timing sequences (unbounded in principle for a long session) | Keeps per-session state bounded; only the first N packets are used for TLS/QUIC-fingerprint-adjacent sequence features |
| **Static reference tables (offline-trained, not updated online)** | N-gram/language-model scoring for domain names, known-fingerprint lookup lists | Some signals (e.g., "does this look like English") aren't learnable from a short streaming window and require a precomputed reference — flagged explicitly for leakage discipline in §8 |

All keyed state (per-source, per-destination, per-src-dst-pair, per-domain, per-JA3) is subject to the expiry/eviction policy in §9 to keep total memory bounded.

---

## 2. DDoS Features (SYN/UDP/spoofed-source)

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `dst_packet_rate` | Packets/sec arriving at a destination | `dst_ip`, `packet_count`, `start_time`/`end_time` | Per destination IP | Short sliding window (e.g., 1–10s) | DDoS | Sliding-window sum, updated per incoming packet/flow record |
| `dst_byte_rate` | Bytes/sec arriving at a destination | `dst_ip`, `byte_count` | Per destination IP | Same short sliding window | DDoS | Sliding-window sum |
| `src_ip_entropy_toward_dst` | Shannon entropy of the source-IP distribution contacting one destination | `src_ip`, `dst_ip` | Per destination IP | Same short sliding window | DDoS | Count-Min Sketch keyed by (dst, src) to approximate the per-source frequency distribution, combined with a distinct-count (HLL) estimate; entropy is computed incrementally each time the window's sketch is queried |
| `syn_no_completion_ratio` | Fraction of flows toward a destination showing SYN without a corresponding ACK-completed pattern | `tcp_flags_cumulative` | Per destination IP | Same short sliding window | DDoS | Two incrementing counters (SYN-seen, completed) per destination, ratio computed on read |
| `ttl_variance_toward_dst` | Variance of observed TTL values toward a destination (spoofed sources often show inconsistent TTLs) | TTL (packet field, PCAP-sourced) | Per destination IP | Same short sliding window | DDoS | Welford's incremental variance, keyed by destination |
| `unique_src_count_toward_dst` | Approximate count of distinct source IPs contacting a destination | `src_ip`, `dst_ip` | Per destination IP | Same short sliding window | DDoS | HyperLogLog keyed by destination |

---

## 3. C2 Beaconing Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `interarrival_mean_pair` | Running mean of inter-arrival time between successive flows on the same src-dst pair | `start_time`, `src_ip`, `dst_ip` | Per (src, dst) pair | Long horizon (hours–days), decay-based rather than a fixed window | C2 | Welford's incremental mean, keyed by (src, dst) |
| `interarrival_variance_pair` | Running variance of the same inter-arrival series | Same | Per (src, dst) pair | Same long horizon | C2 | Welford's incremental variance, same key |
| `periodicity_score_pair` | Coefficient of variation (`std / mean`) of inter-arrival times — lower values indicate more regular, clock-like beaconing | Derived from the two features above | Per (src, dst) pair | Same long horizon | C2 | Computed on read from the two running Welford accumulators — no extra state needed |
| `destination_repeat_count_pair` | Count of flows observed between the same src-dst pair within the horizon | `src_ip`, `dst_ip`, `start_time` | Per (src, dst) pair | Long horizon, with decay (see §9) | C2 | Incrementing counter with exponential decay applied on read, so old activity gradually stops contributing |
| `flow_size_consistency_pair` | Variance of `byte_count` across the repeated flows in the pair's series (beacons are often near-identical size) | `byte_count` | Per (src, dst) pair | Same long horizon | C2 | Welford's incremental variance |
| `unique_destination_count_src` | Approximate distinct destination count for a source, over a long horizon | `src_ip`, `dst_ip` | Per source IP | Long horizon | C2 (used to distinguish "few fixed destinations" beaconing from broad multi-destination behavior) | HyperLogLog keyed by source |

---

## 4. DGA Domain Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `domain_char_entropy` | Shannon entropy of the characters in a single queried domain name | `query_name` (DNSRecord) | Per individual DNS query | None — computed directly on the single record, no window needed | DGA | Direct computation at ingestion (character frequency histogram over one string, O(length of string), no state carried between queries) |
| `domain_ngram_score` | Likelihood of the domain name under a precomputed natural-language n-gram model — low score suggests algorithmic generation | `query_name` | Per individual DNS query | None (scored against a static reference table, not a live window) | DGA | Direct lookup/scoring against an offline-trained n-gram frequency table (see leakage note in §8 — this table must be built only from data available before the evaluation period) |
| `domain_length` | Character length of the queried domain | `query_name` | Per individual DNS query | None | DGA, DNS tunnelling | Trivial direct computation |
| `nxdomain_ratio_host` | Fraction of a host's DNS queries in the window that resolved to NXDOMAIN | `response_code`, `src_ip` (DNSRecord) | Per querying host | Short-to-medium sliding window (minutes) | DGA | Two incrementing counters (NXDOMAIN, total) per host, ratio on read |
| `query_rate_host` | DNS queries/sec from a host | `src_ip`, `timestamp` | Per querying host | Same short-to-medium window | DGA | Sliding-window count |
| `unique_domain_count_host` | Approximate distinct domain count queried by a host in the window | `src_ip`, `query_name` | Per querying host | Same window | DGA | HyperLogLog keyed by host |

---

## 5. DNS Tunnelling Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `query_length_avg_host` | Running average query length for a host | `query_name` length, `src_ip` | Per querying host | Short-to-medium sliding window | DNS tunnelling | Welford's incremental mean |
| `query_length_max_host` | Maximum query length observed for a host in the window | Same | Per querying host | Same window | DNS tunnelling | Sliding-window max (maintained via a monotonic deque or simple re-scan on a short window) |
| `record_type_distribution_host` | Proportion of queries by record type (A/AAAA/TXT/NULL/etc.) for a host | `query_type`, `src_ip` | Per querying host | Same window | DNS tunnelling | Per-type incrementing counters, proportions computed on read |
| `response_size_avg_domain` | Running average DNS response size for a specific domain | `response_size`, `query_name` | Per destination domain | Same window | DNS tunnelling | Welford's incremental mean, keyed by domain |
| `query_concentration_host_domain` | Count of queries from a host to one specific domain, relative to that host's total query count | `src_ip`, `query_name` | Per (host, domain) pair | Same window | DNS tunnelling | Two incrementing counters (per-pair count, per-host total), ratio on read |
| `doh_dot_flag` | Whether this host's DNS traffic is using an encrypted transport (limits which of the above fields are even populated) | `transport` (DNSRecord) | Per flow/host | N/A — a flag, not a windowed statistic | DNS tunnelling, DGA (governs feature availability) | Direct pass-through from the DNSRecord's `transport` field |

---

## 6. Encrypted-Session Malware Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `ja3_identity` | The JA3 hash itself, used as a categorical lookup key (against a static known/suspicious-fingerprint reference list) rather than a numeric feature | `ja3` (TLSQUICMetadata) | Per session | None — direct value | Encrypted-session malware | Direct pass-through; matching against the static reference table happens at scoring time, not during feature computation |
| `ja3_rarity_score` | How rare this JA3 fingerprint is relative to recently observed traffic — a fingerprint seen only once or twice recently is more suspicious than a very common one | `ja3` | Global (across all sessions) | Medium-to-long sliding window | Encrypted-session malware | Count-Min Sketch keyed by JA3 hash over the window, rarity computed as inverse of estimated frequency on read |
| `packet_size_prefix_mean` / `packet_size_prefix_variance` | Mean/variance of the first N packet sizes observed so far in the session (N fixed, e.g. 20) | `packet_sizes` (FlowRecord, bounded prefix) | Per session | Bounded prefix, not time-windowed — "first N packets seen so far," which is inherently causal since it only ever includes packets already observed | Encrypted-session malware | Welford's incremental mean/variance, updated as each of the first N packets arrives; frozen once N is reached |
| `interpacket_timing_prefix_mean` / `interpacket_timing_prefix_variance` | Mean/variance of inter-arrival times among the first N packets of the session | `packet_timestamps` (FlowRecord, bounded prefix) | Per session | Same bounded prefix | Encrypted-session malware | Welford's incremental mean/variance |
| `sni_present_flag` | Whether an SNI value was observed at all (absence itself is informative — could indicate ECH use) | `sni` (TLSQUICMetadata) | Per session | None | Encrypted-session malware | Direct boolean pass-through |
| `session_duration_so_far` | Elapsed time since the session began, updated as the session continues | `start_time`, current time | Per session | None — a running elapsed-time value | Encrypted-session malware | Simple subtraction, updated per observed packet |

---

## 7. Reconnaissance / Port-Scanning Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `unique_dst_port_count_src` | Distinct destination ports contacted by a source | `src_ip`, `dst_port` | Per source IP | Short sliding window (seconds–minutes) | Reconnaissance | **Exact** bitmap counting (port space is bounded at 65,536 values, so an exact per-source bitset is cheap — no need for an approximate sketch here) |
| `unique_dst_host_count_src` | Distinct destination hosts contacted by a source | `src_ip`, `dst_ip` | Per source IP | Same short window | Reconnaissance | HyperLogLog keyed by source (IP space is effectively unbounded, unlike ports) |
| `scan_attempt_rate_src` | Connection attempts/sec from a source | `src_ip`, `start_time` | Per source IP | Same short window | Reconnaissance | Sliding-window count |
| `flow_completion_ratio_src` | Fraction of a source's flows that look incomplete (SYN-only-type flag patterns) | `tcp_flags_cumulative`, `src_ip` | Per source IP | Same short window | Reconnaissance | Two incrementing counters (incomplete, total) per source, ratio on read |

---

## 8. Data-Exfiltration Features

| Feature | Definition | Required raw fields | Scope | Window | Detector | Online computation |
|---|---|---|---|---|---|---|
| `outbound_inbound_byte_ratio_flow` | Ratio of outbound to inbound bytes within a single flow | `fwd_byte_count`, `bwd_byte_count` | Per flow | None — computed per-flow as it closes/updates | Exfiltration | Direct division, recomputed as fwd/bwd counters update during the flow's lifetime |
| `cumulative_outbound_volume_host` | Running sum of outbound bytes from a host over a rolling window | `direction`, `byte_count`, `src_ip` | Per host | Medium-to-long rolling window (e.g., hourly) | Exfiltration | Sliding-window sum, or EWMA for a smoother long-horizon baseline |
| `destination_novelty_flag` | Whether this destination has been contacted by this host before, within a longer historical horizon | `src_ip`, `dst_ip` | Per (host, destination) pair | Long historical horizon (days), approximate | Exfiltration | Bloom filter keyed by (host, destination), checked-then-inserted on each new pair observed — bounded memory even as the destination space grows |
| `outbound_baseline_deviation_host` | How far a host's current outbound volume deviates from its own established baseline | `cumulative_outbound_volume_host` (above) plus a longer-horizon baseline | Per host | Short window compared against a long-horizon EWMA baseline | Exfiltration | EWMA/EWMV maintains the "normal" baseline per host; deviation is `(current − EWMA_mean) / EWMA_stddev`, a z-score-style computation, on read |

---

## 9. Causality, Leakage, and Data-Quality Handling

### 9.1 Look-Ahead Leakage

- **Windowed features:** every sliding/tumbling window is watermark-bound — a feature value computed "as of" event time `t` only ever includes raw records with timestamp `≤ t`. Any record that arrives late but is timestamped before `t` still counts, provided it arrives within the allowed lateness grace period (§9.4); once that period passes, the window has emitted its value and is not retroactively revised.
- **Bounded-prefix session features** (packet-size/timing prefixes in §6): causal by construction, since "first N packets observed so far" can only ever contain packets already seen.
- **Static reference tables** (n-gram model in §4, known-fingerprint lists in §6): these are the one place leakage can hide subtly. The rule: any such table must be built exclusively from data whose timestamp precedes the evaluation/test period. Building or refreshing the n-gram model using domains seen during the test window — even indirectly — would leak future information into what looks like a static, timeless artifact. This must be enforced as a data-pipeline discipline (training/reference-table-build cutoff date), not something the feature computation itself can self-check.
- **Train/test split consistency:** consistent with the earlier data-quality task, all windowed feature computation during training must itself be done in strict time order (walk-forward), never by computing a feature over a window that straddles the train/test boundary using post-split data.

### 9.2 Missing Records

- If a required raw field for a feature is absent (e.g., a dropped packet during a high-throughput burst, per the earlier data-quality notes) that feature computation returns **null/undefined for that update**, not a default of zero — a silent zero would bias rate- and ratio-based features (e.g., making a DDoS burst look smaller than it was, or an exfiltration ratio look more balanced than it was).
- A per-window **completeness flag** is maintained alongside each windowed aggregate, indicating whether any expected-but-missing records were detected during that window (e.g., via sequence-number or expected-flow-count heuristics, if the source format provides them) — downstream consumers can choose to distrust or discount features flagged as computed over incomplete data. Precisely how this completeness signal is derived from the capture layer is a downstream design detail, not resolved here.

### 9.3 Duplicate Records

- Before any feature update, incoming records are deduplicated against the same composite key already established (timestamp + 5-tuple, or `flow_id` where available) using a short-term membership check (e.g., a bounded, time-expiring deduplication set/Bloom filter) so a record replayed or double-mirrored at the capture stage does not double-count into rate, volume, or fan-out features.
- Deduplication state itself is bounded and expires — it only needs to catch near-duplicate arrivals within a short operational window (e.g., the same few seconds), not detect a duplicate arriving hours later, which is a different (out-of-order/replay) concern handled separately.

### 9.4 Out-of-Order Events

- Streaming ingestion assumes a **bounded allowed-lateness grace period** per window (a standard watermarking approach): a window's feature output is held open briefly past its nominal end time to admit slightly late-arriving records (e.g., from network jitter or a second capture point with a different clock offset), then finalized.
- Records arriving **after** the grace period has closed for their window are logged as late-dropped rather than silently discarded or used to retroactively mutate an already-emitted feature value — retroactively changing a feature (and therefore possibly an alert) after the fact would itself create a leakage-adjacent inconsistency between what was "known" at alert time and what's stored afterward.
- The size of the grace period is itself a tunable parameter balancing latency (a core PS requirement) against completeness — a longer grace period catches more late data but delays every alert; this tradeoff is a team decision to tune later, not resolved here.

### 9.5 Window Expiry

- **Short windows** (DDoS, reconnaissance — seconds to a couple of minutes): plain tumbling/sliding expiry; old data simply ages out of the window naturally, and per-key state (e.g., per-destination counters) can be fully discarded once the window closes and no more updates are expected.
- **Long windows** (C2 beaconing, exfiltration baselining — hours to days): storing the full raw event history per key for this horizon is not memory-feasible at scale. Instead, only **sufficient statistics** are retained per key (running count, Welford mean/variance accumulators, EWMA state, last-seen timestamp) — never the full list of past events — so memory per key stays constant regardless of how long the horizon is.
- **Inactive-key garbage collection:** any per-key state (a src-dst pair, a host, a domain) that has seen no updates for longer than a defined inactivity horizon (e.g., 24–48 hours, a tunable team decision) is evicted entirely, preventing unbounded growth from one-off historical contacts that are no longer relevant to current detection.

### 9.6 High-Cardinality Values

- **Unbounded key spaces** (source/destination IPs, domain names, JA3 hashes): addressed throughout via approximate structures — HyperLogLog for distinct counts, Count-Min Sketch for frequency/entropy estimation, Bloom filters for membership/novelty checks — all of which trade a small, known, tunable error rate for bounded memory regardless of how many distinct values are actually seen.
- **Bounded key spaces** (destination ports): handled with *exact* structures (bitmaps) since the space is small enough that approximation isn't necessary or beneficial.
- **Per-key state table growth:** in addition to the above sketches, any exact per-key state table used for smaller aggregations (e.g., per-host counters) is bounded via the inactivity-eviction policy in §9.5, preventing the state table itself from growing without bound even where individual counters are exact.
- **Sequence-field cardinality:** packet-size/timing sequences are capped at a fixed prefix length (§6) specifically to prevent a single long-lived session from growing its state without bound.

---

## 10. Final Inference Feature Schema

The consolidated feature vector actually handed to a model at inference time, grouped by detector. (Model choice, feature selection/pruning, and normalization/scaling are explicitly **not** decided here — this is the causal, computed feature surface available for that later step to draw from.)

| Detector | Feature vector fields |
|---|---|
| **DDoS** | `dst_packet_rate`, `dst_byte_rate`, `src_ip_entropy_toward_dst`, `syn_no_completion_ratio`, `ttl_variance_toward_dst`, `unique_src_count_toward_dst` |
| **C2 Beaconing** | `interarrival_mean_pair`, `interarrival_variance_pair`, `periodicity_score_pair`, `destination_repeat_count_pair`, `flow_size_consistency_pair`, `unique_destination_count_src` |
| **DGA Domains** | `domain_char_entropy`, `domain_ngram_score`, `domain_length`, `nxdomain_ratio_host`, `query_rate_host`, `unique_domain_count_host` |
| **DNS Tunnelling** | `query_length_avg_host`, `query_length_max_host`, `record_type_distribution_host`, `response_size_avg_domain`, `query_concentration_host_domain`, `doh_dot_flag` |
| **Encrypted-Session Malware** | `ja3_identity`, `ja3_rarity_score`, `packet_size_prefix_mean`, `packet_size_prefix_variance`, `interpacket_timing_prefix_mean`, `interpacket_timing_prefix_variance`, `sni_present_flag`, `session_duration_so_far` |
| **Reconnaissance/Scanning** | `unique_dst_port_count_src`, `unique_dst_host_count_src`, `scan_attempt_rate_src`, `flow_completion_ratio_src` |
| **Data Exfiltration** | `outbound_inbound_byte_ratio_flow`, `cumulative_outbound_volume_host`, `destination_novelty_flag`, `outbound_baseline_deviation_host` |
| **Every detector (context, not a signal itself)** | `completeness_flag` (per relevant window, from §9.2) — carried alongside the feature vector so a downstream model or rule can discount low-quality windows rather than treating them as equally trustworthy |

---

**No ML models, feature selection/pruning, or normalization/scaling decisions have been made in this document** — this defines the causal, streaming-computable feature surface only, per the agreed task scope.

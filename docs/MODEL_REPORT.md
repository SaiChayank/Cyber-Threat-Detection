# Model report: PS26145 / Univect

One-document summary of the models, engineered features, training and validation.
Compiled on 29 October 2026 from the source files and saved reports named in each
section. Detail documents are linked; they hold the full protocols and history.

**Status: working passive prototype. Final release is NOT READY.** Detector-quality
gates for UDP/C2/recon/exfiltration/encrypted baselines, the DGA guard and DNS
tunnelling remain unresolved (see [final release audit](FINAL_RELEASE_AUDIT.md) and
the 20 October status in [README](../README.md)). Every figure here is a synthetic,
controlled or one-machine result, not field accuracy.

## 1. Overview and passive constraints

The system reads recorded network metadata (classic Ethernet PCAP, replayed
simulated events, or imported NetFlow/IPFIX/sFlow files), builds causal features
per event, scores it with a frozen model and rules, and raises structured alerts
for an analyst dashboard. Detection is designed to be passive:

- The detector never probes hosts, completes a handshake, issues mitigation or
  blocks traffic (checked in `detection/pipeline.py`, `ingest/`; no network calls in
  inference).
- Input files are opened read-only. The offline CLI can run with no network I/O.
- Payloads are not decrypted. TLS and QUIC are read as handshake or flow metadata only.
- Processing is streaming: one event at a time, with bounded state and a
  watermark that drops late events before state changes (`features/extractor.py`).
- The dashboard API binds to loopback. It is an analyst service, not a return
  path to monitored hosts.
- Software tests do not certify physical diode or NIC isolation.

Every alert carries: timestamp, flow ID, threat class, confidence score, severity,
supporting evidence (narrative plus numeric metrics), alert ID, source and
destination address and port, protocol, and detection source (RULE, ML or HYBRID).
Source: `schemas/alert.py`, `detection/pipeline.py` (`AlertEvent.create`).

## 2. Architecture

Pipeline: ingest -> features -> inference -> alerts -> SQLite / SSE -> dashboard.

| Stage | Main files | Role |
| --- | --- | --- |
| Ingest | `ingest/` (PCAP reader, protocol parsers, `flow_export.py`), `schemas/traffic_event.py` | Read-only PCAP and flow-export import; normalise to `TrafficEvent` |
| Features | `features/extractor.py`, `rate_window.py`, `dns_tunnel.py`, `tls_session.py`, `slow_http.py`, `cow_map.py` | Causal bounded state; 20 model inputs plus rule and evidence features |
| Inference | `ml/model.py` (+ `ml/artifact.json`), `detection/pipeline.py`, `detection/dga_rules.py`, `detection/tls_indicators.py` (+ `.json`), `detection/dns_tunnel_candidate.py`, `ml/dga.py` | Gaussian naive Bayes, rules, guards, disabled candidates |
| Alerts | `schemas/alert.py`, `schemas/enums.py`, `detection/pipeline.py` | Alert schema; 30-second in-place deduplication |
| Persistence and stream | `persistence/store.py`, `backend/` | SQLite alert history; FastAPI; sequence-based SSE |
| Dashboard | `frontend/` | Next.js Monitor: filters, detail, JSON export |
| Replay and evaluation | `replay/`, `datasets/evaluate_lab.py`, `benchmarks/` | Offline replay, lab harness, benchmarks |

Design documents: [Expected solution](EXPECTED_SOLUTION.md), [Model and validation](MODEL_AND_VALIDATION.md).

## 3. Models

### 3.1 Active classifier: Gaussian naive Bayes (synthetic-trained)

- Implementation: `ml/model.py`. Portable JSON, not a pickle. Startup checks the
  SHA-256 sidecar and the exact 20-feature order.
- Artifact: `ml/artifact.json`, SHA-256 `4d8e0832...8010` (matches its sidecar).
- Inputs: each feature is passed through `log1p(max(0, x))`. Class variance is floored at 0.03.
  Scores are normalised to a posterior over the eight classes (BENIGN plus seven threats).
- Use: an ML hit needs a non-BENIGN label with posterior >= 0.8 (`detection/pipeline.py`).
- Training data: offline synthetic metadata from `replay/scenarios.py`, not captured malware
  (`provenance` field in the artifact).

### 3.2 Rule layer (active)

Rules run alongside the classifier and set the detection source to RULE or HYBRID
(HYBRID when a rule and the model agree on the same class). Rule hits score 0.8 as
heuristic strength. Rules as coded in `detection/pipeline.py`:

| Threat | Rule (abbreviated) |
| --- | --- |
| DDOS (TCP) | Destination SYN rate >= 1,000 packets/s AND SYN fraction >= 0.70, or slow-HTTP pair with >= 50 slow connections |
| DDOS (UDP) | Destination UDP packet rate >= 1,000 packets/s |
| DDOS (other protocols) | Global packet rate >= 1,000 packets/s |
| RECONNAISSANCE | Source host or port fan-out over 10 s >= 20 (suppressed below 10) |
| BOTNET_C2 | Same-peer history >= 8, IAT mean >= 1 s, IAT CV < 0.05 |
| DNS_TUNNELLING | Default rule: first label >= 50 characters AND TXT or NULL query |
| DATA_EXFILTRATION | Source-forward bytes in 60 s > 20,000,000 |
| ENCRYPTED_MALWARE | Encrypted AND (lab fingerprint risk OR TLS indicator-list hit OR rare-fingerprint regular session) |
| DGA_DOMAINS | Conservative lexical guard (section 3.3) |

Model-only DDOS hits are removed unless the protocol-specific flood rule also holds
(`pipeline.py`, lines 88-95): the classifier cannot raise a flood alone.

### 3.3 DGA: conservative guard (active) and candidates (disabled)

- **Active:** `detection/dga_rules.py::conservative_rule`. First-label entropy >= 3.5,
  bigram surprise >= 0.8 and label length >= 20. A DGA alert also needs a DNS name
  (`pipeline.py`). Known weakness: recall is low on short and word-based families.
- **Disabled candidate 1, `ml/dga_v2.json`** (SHA-256 `c0314dd5...96fc`, `runtime_enabled=false`,
  threshold 0.9). Inspected development comparison: TP46503 / TN14659 / FP251 / FN14074,
  precision 99.46%, recall 76.77%, domain FPR 1.68%. Separate benign-DNS FPR 2.34%
  (FP275 / 11731). Recall and benign-DNS FPR miss the frozen gates (recall >= 80%,
  FPR <= 2%). Disabled. Source: [Model and validation](MODEL_AND_VALIDATION.md).
- **Disabled candidate 2, `ml/dga_weighted_candidate.json`** (SHA-256 `e8182...c130ca`, threshold 0.85,
  not loaded by the default Pipeline). Validation only: TP74242 / TN14958 / FP278 / FN5758,
  precision 99.63%, recall 92.80%, F1 96.09%, domain FPR 1.82%. The reserved final domain set
  and separate benign-DNS set were not materialised, so the result is unmeasured, not passing.
  Source: [weighted candidate](DGA_WEIGHTED_CANDIDATE.md).
- Public-string regression for the active guard (historical): recall 7.97%, precision 100%,
  FPR 0% ([Model and validation](MODEL_AND_VALIDATION.md)).

### 3.4 DNS tunnelling candidate (disabled)

- Default runtime uses the simple long-label TXT/NULL rule (section 3.2).
- Causal multi-label candidate (`detection/dns_tunnel_candidate.py`, `features/dns_tunnel.py`)
  is off by default (`dns_tunnel_candidate=False`) and enabled only by an explicit opt-in or
  `--dns-tunnel-candidate` in the lab harness.
- Historical development validation (2 Oct): candidate TP5 / TN5 / FP0 / FN0; rule-only
  baseline TP0 / TN4 / FP1 / FN5. These are five positives and five negatives, not a formal result.
  Formal protocol: [DNS tunnelling formal validation](DNS_TUNNELLING_FORMAL_VALIDATION.md).

### 3.5 Encrypted-session path: TLS indicator list and rare-fingerprint behaviour

Source: [Encrypted-session detection](ENCRYPTED_SESSION_DETECTION.md) (29 Oct),
`detection/tls_indicators.py`, `detection/tls_indicators.json`.

- **Indicator list:** a session's JA3, JA3S or JA4 matched against
  `detection/tls_indicators.json`. Current content: one JA3 entry, the project's synthetic
  lab fingerprint used by the bundled demo ("not a real malware family"). JA3S and JA4 lists are empty.
- **Behaviour:** a rare client fingerprint (seen from <= 1 client once >= 5 TLS clients
  are observed) in a session with >= 8 packets, size CV <= 0.25, IAT CV <= 0.25 and mean size <= 600 bytes.
- Severity is HIGH. Confidence is a heuristic strength, not a probability.
- Thresholds are development defaults, to be tuned in P0-5 (pending).

### 3.6 Slow-HTTP exhaustion (rule)

Source: [Slow-HTTP detection](SLOW_HTTP_DETECTION.md), `features/slow_http.py`.
A TCP client-to-service pair with >= 50 data-carrying connections that are open >= 30 s at
<= 100 B/s mean client rate triggers DDOS with `ddos_subtype=slow_http` (CRITICAL,
heuristic strength). Request contents are not inspected. Thresholds are development
defaults, pending P0-5.

### 3.7 Confidence semantics

Confidence is either a heuristic rule strength (0.8) or a synthetic-trained
posterior. The evidence field `confidence_kind` says which. Neither is a calibrated
compromise probability. Severity is set separately (`pipeline.py`: DDOS CRITICAL;
ENCRYPTED_MALWARE, DATA_EXFILTRATION, BOTNET_C2 HIGH; others MEDIUM).

## 4. Features engineered

**Frozen 20 model inputs** (`features/extractor.py::FEATURES`, same order as
`ml/artifact.json`): `packet_rate`, `byte_rate`, `source_entropy`, `syn_fraction`,
`iat_mean`, `iat_cv`, `destination_count`, `port_count`, `domain_entropy`, `domain_length`,
`domain_digit_ratio`, `bigram_surprise`, `txt_record`, `encrypted`, `size_cv`,
`egress_bytes`, `byte_ratio`, `reverse_available`, `fingerprint_risk`, `history_count`.

Additional features used by rules and evidence, by threat:

| Threat / group | Feature keys (code names) | Notes |
| --- | --- | --- |
| DDoS, rates (global) | `packet_rate`, `byte_rate`, `rate_window_seconds`, `rate_window_resolution_ms`, `source_entropy`, `source_entropy_partial` | One-second buckets, ten-second denominator |
| DDoS, TCP SYN | `syn_target_packet_rate`, `syn_target_fraction`, `syn_target_fraction_basis`, `syn_target_source_entropy`, `syn_target_source_count_lower_bound`, `syn_target_entropy_partial` | Per destination; explicit initial-SYN counts |
| DDoS, UDP | `udp_target_packet_rate`, `udp_target_byte_rate`, `udp_target_source_entropy`, `udp_target_source_count_lower_bound`, `udp_destination_concentration`, `udp_packet_size_mean`, `udp_packet_size_cv`, `udp_packet_size_basis` | Per destination |
| DDoS, slow HTTP | `slow_http_open_connections`, `slow_http_connections`, `slow_http_mean_age_s`, `slow_http_mean_client_rate_bps`, `slow_http_target` | `features/slow_http.py` |
| C2 timing | `iat_mean`, `iat_cv`, `history_count` (same-peer, source/destination/port), `destination_count` (fan-out) | Peer timing is per source, destination and port |
| DGA and DNS lexical | `domain_entropy`, `domain_label_length`, `domain_digit_ratio`, `bigram_surprise`, `domain_vowel_ratio`, `domain_consonant_run`, `txt_record` | First DNS label; `ml/dga.py::lexical_features` adds log length, hyphen, unique and repeat ratios, and runs |
| DNS tunnelling (candidate) | `dns_query_visible`, `dns_label_count`, `dns_encoded_max_label_length`, `dns_encoded_total_length`, `dns_encoded_entropy`, `dns_base_queries_10s`, `dns_base_unique_ratio_10s`, `dns_base_encoded_queries_10s` | `features/dns_tunnel.py`; disabled by default |
| Encrypted: fingerprints | `fingerprint_risk` (frozen lab JA3), `tls_ja3`, `tls_ja4`, `tls_server_fingerprint` (JA3S), `tls_fingerprint_clients` | JA4 per FoxIO spec; JA3S from ServerHello |
| Encrypted: session size and timing | `tls_session_packets`, `tls_session_size_cv`, `tls_session_iat_cv`, `tls_session_mean_bytes`, `tls_client_population` | Per client/server/service session, 60 s idle restart (`features/tls_session.py`) |
| Recon fan-out | `destination_count`, `port_count`, `syn_fraction` | Ten-second source window |
| Exfiltration | `source_forward_bytes_60s`, `source_forward_byte_rate_10s`, `source_byte_window_resolution_ms`, `byte_ratio`, `observed_byte_ratio`, `observed_byte_ratio_status`, `reverse_available` | Ratio is null when reverse traffic is unobserved |
| Bounded state | `late_events`, `state_evictions`, `window_partial` | Late events dropped; disclosed bounds |

Limits: average bytes per packet in flow summaries is not a packet-size sequence.
Global rates use one-second buckets. Source history is at most 512 events in 60 s
across at most 4,096 sources (`extractor.py`).

## 5. Training approach

What `ml/train.py` does (verified in code):

1. **Synthetic scenario generator.** For each seed and each class, `replay/scenarios.py::scenario(label, seed)`
   produces events. A fresh `FeatureExtractor` is used per (seed, class) experiment, so
   causal state never crosses experiments.
2. **Seed split.** Training seeds 1-30; validation seeds 31-40; test seeds 41-50. Splits are by whole
   experiment. The same generator families supply all splits, so this is lab validation, not a
   family holdout. The historical design note gives 30 experiments per class and 32 events each
   (7,680 training rows, 2,560 per validation or test split). The `ml/evaluation.json` confusion
   matrices agree: 320 rows per class per split.
3. **Fit.** Per-class mean and variance on `log1p` features, variance floored at 0.03, prior = class share of training rows.
4. **Artifact and integrity.** `ml/artifact.json` plus `ml/artifact.sha256`. Writing the artifact
   produces the new hash, and `Model()` verifies it at load. Feature order is checked against `FEATURES`.
5. **Evaluation.** `evaluate()` writes validation and test per-class precision, recall, F1 and confusion
   to `ml/evaluation.json`. `--evaluate-only` writes `ml/runtime_evaluation.json` and does not refit.
6. **Warning.** `python -m ml.train` without `--evaluate-only` overwrites the frozen artifact. Do not run it as a smoke check (README).

Lab-capture route for tuning: recorded, labelled captures are scored with the lab harness
(section 6.3). Thresholds for the TLS behaviour, slow-HTTP and other rules are to be tuned only on
train and validation splits of lab captures, and the test split scored once. **P0-5 (lab tuning) is pending.**
Protocol: [Lab capture protocol](LAB_CAPTURE_PROTOCOL.md).

Encrypted-model training remains BLOCKED on suitable data ([Encrypted data feasibility](ENCRYPTED_DATA_FEASIBILITY.md)).

## 6. Validation approach and results

### 6.1 Controlled per-threat validation (2 Oct 2026, historical, controlled lab cases)

These are scenario-level counts from the 2 October release audit
([FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md)). The release audit reran the same controlled
fixtures in a fresh checkout and reports unchanged counts. The cases are synthetic development
fixtures, not captures from a real lab. They are not field accuracy. Small denominators apply.

| Threat | Fixture | TP / TN / FP / FN | Recall / precision / FPR | Gate result |
| --- | --- | --- | --- | --- |
| SYN DDoS | `ml/syn_flood_validation.json` | 6 / 6 / 0 / 0 | 100% / 100% / 0% | PASS (controlled functional) |
| UDP DDoS | `ml/udp_flood_development.json` | 4 / 2 / 4 / 0 | 100% / 50% / 66.67% | FAIL (benign high-volume clients alert) |
| Spoof indicators | `ml/spoofed_source_validation.json` | 4 / 2 / 4 / 0 | 100% / 50% / 66.67% | Diagnostic only; predicate not enabled |
| Botnet C2 | `ml/c2_beacon_development.json` | 3 / 6 / 2 / 3 | 50% / 60% / 25% | FAIL |
| Recon | `ml/recon_development.json` | 4 / 3 / 3 / 1 | 80% / 57.14% / 50% | FAIL |
| Exfiltration | `ml/exfil_development.json` | 4 / 2 / 4 / 1 | 80% / 50% / 66.67% | FAIL |
| Encrypted indicators | `ml/encrypted_session_validation.json` | 3 / 6 / 4 / 5 | 37.5% / 42.86% / 40% | FAIL |
| DNS tunnel candidate (disabled) | `ml/dns_tunnel_candidate_validation.json` | 5 / 5 / 0 / 0 | 100% / 100% / 0% | Not a gate pass; disabled |

In the release audit, SYN DDoS is the only controlled gate that passes; the other
threats are PARTIAL or FAIL, and the enabled detectors fail their predeclared quality gates. Benign look-alikes (health checks,
authorised scanners, backups, browsing, shared-JA3 applications) produce the false positives.

### 6.2 Synthetic classifier report (`ml/evaluation.json`)

Frozen Gaussian NB, on synthetic lab experiments only. This is not hybrid alert accuracy.

- Macro F1: validation 0.98948; test 0.99025 (values from `ml/evaluation.json`).
- Test per-class recall: BENIGN 0.98125; DDOS 1.0; BOTNET_C2 0.99688; DGA_DOMAINS 1.0; DNS_TUNNELLING 1.0;
  ENCRYPTED_MALWARE 0.94375; RECONNAISSANCE 1.0; DATA_EXFILTRATION 1.0.
- The synthetic fingerprint is a shortcut signal. Scores remain uncalibrated, and the
  report's own caveats say so.

### 6.3 Lab evaluation harness (how to score real lab captures)

Source: [Lab evaluation](LAB_EVALUATION.md), `datasets/evaluate_lab.py`.

- Input: one label file (`ps26145-lab-labels/1`) per classic Ethernet PCAP, with episodes
  (label, scenario, start/end or epoch ms, hosts/CIDRs) and a split (train, validation, test, unassigned).
- Each capture runs through a fresh `Pipeline`, in file order, through the same reader as PCAP upload.
- Metrics: episode recall, time to detect, alert precision per class, benign false alerts per 1,000 benign
  events, ingest health (late events, corrupt packets). The report records SHA-256 of every input.
- Command: `python -m datasets.evaluate_lab run01.labels.json ... --out lab-report.json`.
- Protocol: [Lab capture protocol](LAB_CAPTURE_PROTOCOL.md) (minimum 6 runs per threat class, 3 benign runs per look-alike category, whole-run splits, test scored once).
- **Status: no labelled lab captures have been scored yet (P0-5 pending).** No lab-capture result exists in the repository.

### 6.4 Performance (core and delivery)

Core and delivery are separate scopes. Neither is raw-capture-to-browser throughput.

| Measurement | Value | Source |
| --- | --- | --- |
| Core + SQLite, latest JSON (20 Oct 2026 run) | 20,000 events, 1,170 alerts; **3,955.74 metadata events/s**; p50 0.1704 ms; **p95 0.9790 ms**; gates pass (>= 2,000/s; p95 < 50 ms) | `benchmarks/latest.json` |
| Delivery, API to SQLite to SSE, 20 Oct stored-JSON run | 100/100 accepted, persisted and delivered; **p95 249.29 ms** (gate < 1,000 ms) | [Performance validation](PERFORMANCE_VALIDATION.md) header |
| Core, 2 Oct clean checkout (historical) | 6,248.12 events/s; p95 0.8070 ms | [Final release audit](FINAL_RELEASE_AUDIT.md) |
| Delivery, 2 Oct clean checkout (historical) | 100/100; p95 247.48 ms | Same |
| Core, after slow-HTTP change (29 Oct) | 3,322 events/s; p95 1.08 ms; 1,170 alerts | [Slow-HTTP detection](SLOW_HTTP_DETECTION.md) (not in `benchmarks/latest.json`) |

Discrepancy: the README and performance pages cite other core figures for the 20 October
checkout (for example 4,256.97 events/s). `benchmarks/latest.json`, which is the saved JSON, records 3,955.74.
This report quotes the JSON. The 29 October figure is documented only in prose.

### 6.5 PCAP throughput (full path)

Source: `benchmarks/pcap_throughput_latest.json`, [PCAP throughput](PCAP_THROUGHPUT.md).
Synthetic benign workload: 50,000 packets, 3,091 flows, 5.0 s of capture, one machine.

| Path | Packets/s | Flows/s | Sustained Mbps |
| --- | --- | --- | --- |
| Parse only (reader and adapter) | 51,361 | n/a | 307.3 |
| Full path (parse, features, inference) | **1,301.1** | 80.4 | **7.78** |

**The full PCAP path is below 2,000 packets/s.** It runs at a realtime factor of 0.13 on this
workload. The 2,000 gate applies to flow-summary metadata events (section 6.4), not packets.
The run raised 2 benign `ENCRYPTED_MALWARE` alerts from the rare-fingerprint rule.

## 7. Requirement traceability

The problem-statement letter labels (a-f, a-e) are not present in the files read for
this report. Rows below use the requirement names of [Expected solution](EXPECTED_SOLUTION.md)
and the seven detector labels. The letter mapping is **not verified**.

| Requirement | Status | File / document |
| --- | --- | --- |
| Read-only ingest (no probe, no return path, no blocking) | Implemented (software; not physical isolation) | `ingest/`, `detection/pipeline.py`, [Final release audit](FINAL_RELEASE_AUDIT.md) |
| Causal feature extraction and AI/ML inference | Implemented | `features/extractor.py`, `ml/model.py`, `ml/train.py` |
| DDoS: SYN / volumetric / UDP | Partial (SYN controlled PASS; UDP FPs) | `detection/pipeline.py`, `docs/SYN_FLOOD_VALIDATION.md`, `docs/UDP_FLOOD_VALIDATION.md` |
| DDoS: slow HTTP | Implemented; Not validated on real captures | `features/slow_http.py`, [Slow-HTTP detection](SLOW_HTTP_DETECTION.md) |
| Botnet C2 beaconing | Partial | `features/extractor.py`, `docs/C2_BEACON_VALIDATION.md` |
| DGA | Partial (active guard low recall; candidates disabled) | `detection/dga_rules.py`, `ml/dga_v2.json`, [DGA development](DGA_DETECTION.md) |
| DNS tunnelling | Partial (default rule; candidate disabled) | `detection/pipeline.py`, `detection/dns_tunnel_candidate.py`, [DNS tunnelling validation](DNS_TUNNELLING_FORMAL_VALIDATION.md) |
| Encrypted-session indicators (JA3/JA4/JA3S, session size and timing, rarity) | Implemented; Not validated on real captures; quality FAIL | `schemas/tls_metadata.py`, `features/tls_session.py`, `detection/tls_indicators.py`, [Encrypted-session detection](ENCRYPTED_SESSION_DETECTION.md) |
| Reconnaissance | Partial | `detection/pipeline.py`, `docs/RECON_VALIDATION.md` |
| Possible exfiltration | Partial | `detection/pipeline.py`, `docs/EXFIL_VALIDATION.md` |
| Standardised alerts (fields, severity separate from score) | Implemented | `schemas/alert.py`, `detection/pipeline.py` |
| Dashboard, SSE, persistence and restart | Implemented (local, single worker) | `frontend/`, `backend/`, `persistence/store.py` |
| Streaming with bounded latency | Implemented (controlled demo and core scope) | `features/extractor.py`, `benchmarks/run.py` |
| Core throughput >= 2,000 metadata events/s, p95 < 50 ms | Implemented (one machine, synthetic) | `benchmarks/latest.json` |
| Full-path packet throughput | Partial: 1,301 packets/s, below 2,000 | `benchmarks/pcap_throughput_latest.json` |
| Delivery p95 < 1,000 ms (API to SSE) | Implemented (loopback only) | [Performance validation](PERFORMANCE_VALIDATION.md) |
| NetFlow, IPFIX, sFlow import | Implemented as file import; no live collector | `ingest/flow_export.py`, [Flow export import](FLOW_EXPORT_IMPORT.md) |
| Lab evaluation of real captures | Implemented (harness); Not validated on real captures (P0-5 pending) | `datasets/evaluate_lab.py`, [Lab evaluation](LAB_EVALUATION.md) |
| Reproducible models and integrity | Implemented for active model; all six model artifacts keep their hashes through a Windows checkout (H1 fixed; verified 29 Oct in a fresh clone) | `ml/artifact.json`, [Final release audit](FINAL_RELEASE_AUDIT.md) |
| Detector quality gates | FAIL (B1, B2, B3 open) | [Final release audit](FINAL_RELEASE_AUDIT.md) |

## 8. Known limitations and next steps

**Detector quality (blockers).**
- Enabled UDP, C2, recon, exfiltration and encrypted baselines fail their hard benign controls. Some
  positives and negatives look identical in the available metadata, so threshold tuning cannot prove intent.
- DGA: the active guard has weak recall on short and word-based names. Both candidates are disabled,
  and their reserved and separate benign-DNS evaluations are missing.
- DNS tunnelling: no eligible, labelled, full-snaplen real-tool data set exists. The candidate
  is disabled.

**Training and data.**
- The active model is trained only on synthetic scenarios from the same generator families.
  Its test seeds have already been inspected, so they are not an independent holdout.
- The lab fingerprint is a shortcut. Correlated features can give overconfident scores.
- No labelled lab captures have been scored. Thresholds (TLS behaviour, slow-HTTP, rules) are untuned.
  Tuning is P0-5, pending.

**Capture and protocol coverage.**
- No live NetFlow, IPFIX or sFlow collector. Only file import from captured export datagrams.
- Ethernet PCAP and PCAPNG only (`ingest/pcapng.py`: enhanced packet blocks; other link types are rejected). A TLS record or DNS/TCP message is read when it fits one segment or spans in-order segments (bounded, `docs/TCP_REASSEMBLY.md`); there is no full
  TCP reassembly, and TLS 1.3 encrypts the handshake messages after the ServerHello, so only the ServerHello is fingerprinted.
- No raw QUIC handshake (JA4) fingerprinting, deliberately: it requires decrypting the Initial packet, which the constraints forbid. A clear-header QUIC fingerprint is used instead. JA4+ variants (JA4S, JA4X) are not implemented.
- Rarity needs a client population. Single-host captures cannot trigger the behaviour path.
- DoH and DoT hide DNS names. Segmented DNS/TCP questions are not reconstructed.

**Performance.**
- Full packet path (1,301 packets/s over 50,000 packets) is below 2,000 packets/s. Parsing is not the bottleneck; the
  extractor rescans each source's retained history per event, so throughput falls as histories fill
  (`PCAP_THROUGHPUT.md`).
- Measurements are one-machine, one-process results, and the core JSON and prose figures differ by date (section 6.4).

**Packaging.** The 2 Oct audit's H1 issue (three inactive public-model JSON files failing hash checks after a Windows CRLF
checkout) is fixed by `.gitattributes` `-text` rules; the 29 Oct fresh clone matches all hashes and a checkout regression test covers it.

**Next steps (from the project documents).**
1. Record labelled lab captures per [Lab capture protocol](LAB_CAPTURE_PROTOCOL.md), with the split fixed before scoring.
2. Score train and validation with `datasets/evaluate_lab`, then tune TLS, slow-HTTP and other thresholds (P0-5).
3. Score the test split once. Enable a detector only if it passes its predeclared gate.
4. Decide whether to bound the per-source history scan (a feature-contract change) to raise full-path throughput.

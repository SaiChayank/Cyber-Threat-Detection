# SIH PS26145 — UNIFIED FINAL MASTER BLUEPRINT & EXECUTION ROADMAP
> Historical design proposal. For the current implementation and screenshot-governed requirements, see `EXPECTED_SOLUTION.md`, `MODEL_AND_VALIDATION.md`, and the root README. Performance figures below are proposed targets, not measured results.
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | **Category:** Software  
**Document Status:** AUTHORITATIVE SINGLE SOURCE OF TRUTH (v2.0 Unified)  
**Compilation Date:** September 2026  

---

## 1. Executive Summary & Governing Air-Gap Invariants

### 1.1 Objective
Design and implement an end-to-end AI/ML streaming pipeline that passively ingests a **one-directional, uniflow stream of simulated IP traffic** (e.g., from an optical data diode or mirror TAP) and detects, classifies, scores, and explains cyber threats in **near real-time** ($\text{latency} < 50\text{ ms}$, $\text{throughput} \ge 2,000\text{ flows/sec}$ up to $20,000+\text{ flows/sec}$) with **zero interaction** with the monitored network.

### 1.2 The Seven Non-Negotiable Air-Gap Invariants
1. **Zero Egress Transmission:** The capture interface (`veth-mon` or TAP NIC) must never emit an Ethernet frame, IP packet, ARP request/reply, or ICMP message. Egress is hard-blocked at the kernel level (`tc` filter action drop).
2. **Zero Return-Path Dependency:** All session tracking, protocol parsing, and threat classification must function correctly with zero reverse packets (`bytes_backward = 0`). Missing reverse packets degrade gracefully to `null`, never to crashes or synthetic zero-filling.
3. **No Active Probing:** Reverse DNS lookups, WHOIS queries, TCP handshakes, ICMP pings, or active port scans by the detector are strictly forbidden.
4. **No Inline Interference:** The detector operates purely out-of-path. It cannot drop, delay, rate-limit, or reshape packets on the monitored link. Monitored traffic flows unhindered if the detector halts.
5. **No Payload Decryption:** TLS 1.2/1.3, DTLS, and QUIC application payloads are treated as opaque ciphertext. Analysis is strictly restricted to unencrypted handshake metadata (JA3/JA3S/JA4/JA4S, SNI, ALPN, cipher lists) and packet sequence dynamics (SPLT: Sequence of Packet Lengths and Times).
6. **Continuous Incremental Streaming:** Ingestion, state maintenance, feature extraction, and inference run on an event-driven rolling window basis with bounded latency ($< 50\text{ ms}$ processing time), never batch-after-the-fact processing.
7. **Complete Metric Decoupling:** Calibrated statistical confidence ($0.0 \le C \le 1.0$) is mathematically decoupled from operational threat severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

## 2. Requirement Traceability Matrix

| Req ID | SIH Problem Specification | Implementation Component | Verification Proof | Demo Step |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-01** | Passive, Unidirectional TAP | `deploy/scripts/setup_mon_iface.sh` | Kernel `tc` egress filter drops 100% of outbound frames; zero TX on wire | Step 2 |
| **REQ-02** | No Return-Path Dependency | `pipeline/features/extractor.py` | `tap_mode="unidirectional"` safely ignores missing reverse packets | Step 2 |
| **REQ-03** | No Payload Decryption | `pipeline/features/tls_metadata.py` | Features use ClientHello parameters (JA3/JA4) and SPLT length dynamics | Step 7 |
| **REQ-04** | Streaming Ingestion ($< 50\text{ ms}$) | `pipeline/streaming/ring_buffer.py` | Sliding ring buffers update causally; alerts emit before PCAP EOF | Steps 3, 10 |
| **REQ-05** | Demonstrated Throughput | `benchmarks/run_suite.py` | Benchmark script measures sustained flows/sec, Mbps, and latency | Step 14 |
| **REQ-06** | Volumetric / Protocol DDoS | `pipeline/detection/rules_fast_path.py` | Rate counters ($> 10\text{k pps}$), SYN:ACK ratio, source-IP entropy | Step 4 |
| **REQ-07** | Botnet C2 Beaconing | `pipeline/detection/ml_detectors.py` | Welford algorithm calculates inter-arrival timing mean ($\mu$) and variance (CV) | Step 5 |
| **REQ-08** | DGA Domains & DNS Tunnel | `pipeline/features/entropy.py` | Shannon character entropy, bi-gram perplexity, TXT/NULL record ratios | Step 6 |
| **REQ-09** | Encrypted Malware Indicators | `pipeline/detection/rules_fast_path.py` + `ml_detectors.py` | JA3 blocklist matching combined with SPLT length distribution vectors | Step 7 |
| **REQ-10** | Reconnaissance & Port Scans | `pipeline/streaming/state_manager.py` | Destination port and host fan-out counters within sliding 10s windows | Step 8 |
| **REQ-11** | Data Exfiltration | `pipeline/features/extractor.py` | Asymmetric egress byte volume and mean packet sizes on outbound flows | Step 9 |
| **REQ-12** | Standardized Alert Schema | `pipeline/schemas/alerts.py` | Outputs `timestamp`, `flow_id`, `threat_class`, `confidence_score`, `supporting_evidence` | Step 11 |
| **REQ-13** | SOC Analyst Visualization | `dashboard/src/App.tsx` | React 18 dashboard rendering live SSE/WebSocket alert streams and replay controls | Steps 10-13 |
| **REQ-14** | Technical Documentation | `docs/*.md` | Architectural blueprints, mathematical feature specs, and validation reports | Review |

---

## 3. End-to-End System Architecture

```
                  MONITORED UNIDIRECTIONAL LINK (TAP / DATA DIODE)
                                         │
                                         ▼ (Read-Only Mirror / Egress Blocked)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ FASTAPI RUNTIME MONOLITH (Python 3.11+ / asyncio)                                      │
│                                                                                        │
│ ┌─────────────────────────┐                                                            │
│ │ 1. Passive Ingest Layer │ AF_PACKET Raw Socket Listener / Chunked PCAP Streamer      │
│ └───────────┬─────────────┘                                                            │
│             │ Raw binary frames + nanosecond timestamps                                │
│             ▼                                                                          │
│ ┌─────────────────────────┐                                                            │
│ │ 2. Zero-Copy Parser     │ dpkt / scapy decoders (Ethernet, IPv4/v6, TCP, UDP, DNS, TLS)│
│ └───────────┬─────────────┘                                                            │
│             │ Canonical Records (FlowRecord, DNSRecord, TLSMetadataRecord)             │
│             ▼                                                                          │
│ ┌─────────────────────────┐                                                            │
│ │ 3. Streaming State      │ Circular Ring Buffers (1s, 10s, 60s)                       │
│ │ & Feature Engine        │ Welford Accumulators + LRU Host Table (50k active limit)   │
│ └───────────┬─────────────┘                                                            │
│             │ 22-Dimensional Continuous Feature Vector x ∈ ℝ²² (with Readiness Flags)  │
│             ▼                                                                          │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 4. Two-Tier Detection Engine                                                       │ │
│ │ • Tier 1: Fast-Path Rule Arbiter (< 0.2 ms) — Volumetric DDoS, SYN Floods, Scans   │ │
│ │ • Tier 2: Specialized LightGBM/XGBoost Classifiers (C2, DGA, Tunnel, Malware, Exfil)│ │
│ └───────────────────────────────────┬────────────────────────────────────────────────┘ │
│                                     │ Raw Class Probabilities & Rule Signals           │
│                                     ▼                                                  │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 5. Scoring & Evidence Engine                                                       │ │
│ │ • Isotonic Confidence Calibration: C = IsotonicRegress(P_raw) ∈ [0.0, 1.0]         │ │
│ │ • Threat Severity: Score_sev = W_threat × C × V_impact (LOW to CRITICAL)           │ │
│ │ • Explainability: Templated Evidence + On-Demand TreeSHAP Attribution              │ │
│ └───────────────────────────────────┬────────────────────────────────────────────────┘ │
│                                     │ Standardized Alert JSON Records                  │
│                                     ▼                                                  │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 6. Storage & Event Bus                                                             │ │
│ │ • 30s Sliding Window Deduplication & Suppression Cache                             │ │
│ │ • SQLite WAL Persistence (Dev) / PostgreSQL (Prod)                                 │ │
│ │ • Server-Sent Events (SSE) Broadcast (`/api/v1/alerts/live`) + WS Telemetry       │ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────┬─────────────────────────────────────────────────┘
                                       │ SSE Alert Stream + REST Telemetry
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SOC ANALYST DASHBOARD (React 18 + Vite + TypeScript + Tailwind CSS)                    │
│ • Virtualized Live Alert Stream (60 FPS) with Severity Badges & Confidence Meters      │
│ • Detail Slide-over Modal with TreeSHAP Waterfall Chart & Deterministic Narratives     │
│ • Paced PCAP Replay Controller (1×, 2×, 5×, MAX Benchmark) & Telemetry Dials           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Canonical Data Schemas

### 4.1 `FlowRecord`
```python
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass(slots=True)
class FlowRecord:
    flow_id: str                      # sha256(src_ip, dst_ip, src_port, dst_port, proto, start_ms)[:32]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int                     # 6 = TCP, 17 = UDP, 1 = ICMP
    timestamp_start: float            # Epoch timestamp in milliseconds
    timestamp_end: float              # Updated on last observed packet
    packets_forward: int = 0
    packets_backward: int = 0         # Maintained at 0 on unidirectional links
    bytes_forward: int = 0
    bytes_backward: int = 0           # Maintained at 0 on unidirectional links
    tcp_flags_forward: int = 0        # Bitwise OR cumulative flags seen
    tcp_flags_backward: int = 0
    inter_arrival_times: List[float] = field(default_factory=list)
```

### 4.2 `DNSRecord`
```python
@dataclass(slots=True)
class DNSRecord:
    query_id: int
    query_name: str                   # FQDN (e.g. "x92kmz01.corp-auth.com")
    query_length: int
    query_type: int                   # 1 = A, 16 = TXT, 28 = AAAA, 10 = NULL
    response_code: Optional[int]      # 0 = NOERROR, 3 = NXDOMAIN
    response_bytes: int
    src_ip: str
    timestamp: float
```

### 4.3 `TLSMetadataRecord`
```python
@dataclass(slots=True)
class TLSMetadataRecord:
    flow_id: str
    tls_version: int                  # 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
    ja3_string: str                   # SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats
    ja3_hash: str                     # md5(ja3_string)
    ja4: Optional[str] = None
    cipher_suites: List[int] = field(default_factory=list)
    extension_count: int = 0
    sni: Optional[str] = None
    splt_sequence: List[int] = field(default_factory=list)  # First 20 signed packet lengths
```

---

## 5. Mathematical Feature Definitions (The 22-Vector $x \in \mathbb{R}^{22}$)

All features are strictly **causal** (right-closed $[t - \text{window}, t]$, no future look-ahead):

| Index | Feature Name | Window | Mathematical Formula / Derivation | Target Threat |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `f_pkt_rate_global` | 10s Ring | $N_{\text{packets}} / 10.0$ | DDoS |
| **2** | `f_byte_rate_global` | 10s Ring | $N_{\text{bytes}} / 10.0$ | DDoS |
| **3** | `f_src_ip_entropy` | 10s Ring | $-\sum p(\text{src\_ip}) \cdot \log_2 p(\text{src\_ip})$ | DDoS / Spoof |
| **4** | `f_tcp_syn_ack_ratio` | 10s Ring | $N_{\text{SYN}} / \max(1, N_{\text{ACK}})$ | SYN Flood |
| **5** | `f_c2_iat_mean` | Session | $\mu_{\Delta t}$ via Welford online algorithm | Botnet C2 |
| **6** | `f_c2_iat_cv` | Session | $CV = \sigma_{\Delta t} / \max(0.001, \mu_{\Delta t})$ | Botnet C2 |
| **7** | `f_c2_dst_fan_in` | 60s Ring | Distinct source IPs contacting target IP | Botnet C2 |
| **8** | `f_dns_fqdn_entropy` | Instant | $-\sum p(c) \cdot \log_2 p(c)$ across FQDN characters | DGA |
| **9** | `f_dns_ngram_perplexity` | Instant | $\exp\left(-\frac{1}{N}\sum \log P(c_i \mid c_{i-1})\right)$ via bi-gram model | DGA |
| **10** | `f_dns_query_len` | Instant | $\text{len}(\text{query\_name})$ | DNS Tunnel |
| **11** | `f_dns_subdomain_ratio` | Instant | $\text{len}(\text{subdomain}) / \max(1, \text{len}(\text{query\_name}))$ | DGA / Tunnel |
| **12** | `f_dns_txt_null_ratio` | 60s Ring | $(\text{Count}(\text{TXT}) + \text{Count}(\text{NULL})) / \max(1, \text{Count}(\text{DNS}))$ | DNS Tunnel |
| **13** | `f_dns_cumulative_bytes_per_apex` | 60s Ring | $\sum \text{response\_bytes}$ grouped by apex domain | DNS Tunnel |
| **14** | `f_tls_ja3_risk_score` | Instant | Target-encoded historical threat weight / blocklist match | Encrypted Malware |
| **15** | `f_tls_splt_mean_len` | Session | $\frac{1}{K} \sum_{i=1}^{K} \|L_i\|$ for first $K=20$ packet lengths | Encrypted Malware |
| **16** | `f_tls_cipher_count` | Instant | $\text{len}(\text{cipher\_suites})$ | Encrypted Malware |
| **17** | `f_recon_dst_port_fanout` | 10s Ring | $\text{Count}(\text{Distinct dst\_port})$ per Source IP (HyperLogLog) | Recon / Scans |
| **18** | `f_recon_dst_ip_fanout` | 10s Ring | $\text{Count}(\text{Distinct dst\_ip})$ per Source IP (HyperLogLog) | Recon / Scans |
| **19** | `f_recon_unanswered_syn_ratio` | 10s Ring | $N_{\text{SYN\_only}} / \max(1, N_{\text{total\_flows}})$ | Recon / Scans |
| **20** | `f_exfil_byte_ratio` | Session | $\text{bytes\_out} / \max(1, \text{bytes\_out} + \text{bytes\_in})$ | Data Exfiltration |
| **21** | `f_exfil_egress_volume` | 60s Ring | Cumulative outbound bytes per Source IP | Data Exfiltration |
| **22** | `f_exfil_mean_pkt_size` | Session | $\text{bytes\_out} / \max(1, \text{packets\_out})$ | Data Exfiltration |

### Feature Readiness Semantics
* `NOT_READY`: Insufficient history (e.g., C2 requiring at least 5 completed flows). Value passed as `null`.
* `PARTIAL`: Computable but shorter than nominal window. Evaluated with partial-window training semantics.
* `READY`: Nominal history window elapsed. Normal inference.

---

## 6. Two-Tier Detection & Evidence Engine

```
                                Feature Vector x ∈ ℝ²²
                                          │
                                          ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ TIER 1: FAST-PATH RULE ARBITER (< 0.2 ms)                              │
       │ • Volumetric: f_pkt_rate_global > 10,000 OR f_src_ip_entropy > 0.85   │
       │ • SYN Flood: f_tcp_syn_ack_ratio > 20.0                                │
       │ • Port Sweep: f_recon_dst_port_fanout > 25 distinct ports in 10s       │
       │ • Malicious JA3 Signature: f_tls_ja3_risk_score == 1.0                 │
       └───────────────────┬────────────────────────────────┬───────────────────┘
                           │                                │
            Triggered Hit  │                                │ Clean / Residual
                           ▼                                ▼
       ┌───────────────────────────────┐  ┌─────────────────────────────────────┐
       │ IMMEDIATE FAST-PATH ALERT     │  │ TIER 2: SPECIALIZED LIGHTGBM/XGBOOST│
       │ • Fixed Staged Confidence 0.99│  │ • C2 Beaconing Model                │
       │ • Deterministic Template Text │  │ • DGA Lexical Model                 │
       └───────────────┬───────────────┘  │ • DNS Tunnel Model                  │
                       │                  │ • Encrypted & Exfil Model           │
                       │                  └──────────────────┬──────────────────┘
                       │                                     │ Score > Threshold
                       │                                     ▼
                       │                  ┌─────────────────────────────────────┐
                       │                  │ SPECIALIZED ML ALERT                │
                       │                  │ • Isotonic Calibrated Confidence    │
                       │                  │ • Dynamic TreeSHAP Evidence         │
                       │                  └──────────────────┬──────────────────┘
                       │                                     │
                       └──────────────────┬──────────────────┘
                                          ▼
                               [ Unified Alert Object ]
```

### 6.1 Calibration & Severity Formulas
1. **Calibrated Confidence ($C$):**
   Raw model output probability $P_{\text{raw}}$ is mapped through a pre-fitted Isotonic Regression step function:
   $$C = \text{IsotonicRegress}_{\text{threat}}(P_{\text{raw}}) \in [0.0, 1.0]$$
2. **Operational Severity Score ($\text{Score}_{\text{sev}}$):**
   $$\text{Score}_{\text{sev}} = W_{\text{threat}} \times C \times V_{\text{impact}}$$
   * **Weights:** $\text{DDoS} = 1.0$, $\text{Exfiltration} = 0.95$, $\text{Botnet C2} = 0.85$, $\text{Encrypted Malware} = 0.80$, $\text{DNS Tunnel} = 0.75$, $\text{Recon} = 0.50$, $\text{DGA} = 0.45$.
   * **Bands:** $\ge 0.75 \to \text{CRITICAL}$, $\ge 0.50 \to \text{HIGH}$, $\ge 0.25 \to \text{MEDIUM}$, $< 0.25 \to \text{LOW}$.

### 6.2 Standardized Alert Schema Contract
```json
{
  "timestamp": 1789456200150.0,
  "flow_id": "9f1b2c3a4e5d6f708192a3b4c5d6e7f8",
  "threat_class": "BOTNET_C2",
  "confidence_score": 0.892,
  "severity": "HIGH",
  "supporting_evidence": "Periodic beaconing identified: mean interval Δt = 30.12s, low CV = 0.038, destination repeat count = 18 flows",
  "alert_id": "c4b8e21a-7f3d-4e9a-8b1c-92f5d6a1b2c3",
  "src_ip": "10.100.0.15",
  "dst_ip": "198.51.100.4",
  "src_port": 49152,
  "dst_port": 443,
  "protocol": 6,
  "detection_source": "ML_SPECIALIZED",
  "occurrence_count": 1
}
```

---

## 7. Synthetic Traffic Lab & Dataset Generation

Since **no official SIH dataset exists**, the project relies on isolated synthetic lab generation:

| Threat Category | Primary Tooling | Scenario Generation Parameters |
| :--- | :--- | :--- |
| **Benign Baseline** | `iperf3`, `TRex`, `curl` | HTTP/HTTPS browsing, Alexa Top-1M DNS lookups, file transfers |
| **DDoS Floods** | `hping3` | SYN flood ($> 20\text{k pps}$), UDP reflection, spoofed source IP entropy |
| **Botnet C2** | Sandboxed emulator / python script | Periodic beaconing at $30\text{s} \pm 20\%$ jitter to fixed command host |
| **DGA Lookups** | Algorithmic generator (DGArchive) | High-entropy pseudo-random domains resulting in NXDOMAIN bursts |
| **DNS Tunnelling** | `dnscat2`, `iodine` | Base64/hex data chunks encoded in TXT and NULL query records |
| **Encrypted Malware** | Custom TLS generator / scapy | Pinned malicious JA3 hashes + low-variance robotic SPLT profiles |
| **Port Scanning** | `nmap`, custom SYN scanner | Fast horizontal sweeps ($> 50$ hosts) and vertical port scans ($> 100$ ports) |
| **Data Exfiltration** | `curl`, `scp` dummy transfers | Asymmetric outbound transfers ($> 50\text{ MB}$, byte ratio $> 20:1$) |

**Curated PCAP Portfolio:** 7 standalone, labeled PCAP captures stored in `data/pcaps/` accompanied by ground-truth JSON manifests.

---

## 8. 15-Minute Live SIH Demonstration Protocol

| Demo Phase | Time Window | Demonstrated Action & Proof | Fallback Plan |
| :--- | :---: | :--- | :--- |
| **1. Environment & Air-Gap** | 0:00 – 3:00 | • Verify SHA-256 model hashes at startup.<br>• Run `ping -I veth-mon 10.100.0.30` $\to$ `Operation not permitted`.<br>• Show `tc filter` rule dropping all outbound frames.<br>• Run benign traffic $\to$ zero false positives. | L1: Switch to local loopback replay. |
| **2. Threat Walkthrough** | 3:00 – 8:00 | • Replay SYN flood $\to$ Tier 1 Fast-Path Rule fires in $< 0.2\text{ ms}$ (CRITICAL).<br>• Replay C2 beacon $\to$ Tier 2 LightGBM model detects periodicity (HIGH).<br>• Replay DGA & DNS Tunnel $\to$ Flags Shannon entropy ($4.68\text{ bits}$) & TXT sizes.<br>• Replay Encrypted Malware $\to$ JA3 match + SPLT length profile (no decryption).<br>• Replay Recon & Exfiltration $\to$ Fan-out alerts & asymmetric byte ratios. | L1: Replay validated backup PCAP file. |
| **3. Forensic Investigation** | 8:00 – 11:00 | • Click live alert card $\to$ open Alert Detail slide-over modal.<br>• Inspect 5-tuple context, calibrated confidence ($89.2\%$), and TreeSHAP waterfall.<br>• Submit analyst feedback (True Positive confirmation). | L2: Load cached alert detail snapshot. |
| **4. Benchmarking & Audit** | 11:00 – 15:00 | • Execute benchmark on 500k-packet capture.<br>• Telemetry dials demonstrate $> 20,000\text{ flows/sec}$ with alert latency $< 15\text{ ms}$.<br>• Display $+0.15\text{ Macro } F_1$ superiority of hybrid ML over static rules alone. | L3: Show pre-generated `throughput_report.json`. |

---

## 9. Final Phase-by-Phase Implementation Roadmap

```
Phase 1: Schemas, Ingest & Zero-Copy Parsers
  │
  ▼
Phase 2: Streaming State & Causal 22-Vector Feature Extractor
  │
  ▼
Phase 3: Synthetic Lab Generators & Curated PCAP Portfolio
  │
  ▼
Phase 4A: Tier 1 Fast-Path Rule Arbiter & Non-ML Baseline
  │
  ▼
Phase 4B: Tier 2 LightGBM Detectors, Calibration & SHAP Evidence
  │
  ▼
Phase 5A: FastAPI Monolith, SQLite WAL Persistence & REST APIs
  │
  ▼
Phase 5B: Streaming Bridge, Deduplication & SSE Broadcast
  │
  ▼
Phase 6: React SOC Dashboard, Virtualized Live Feed & Replay UI
  │
  ▼
Phase 7: End-to-End Compliance Proofs, Benchmarks & Demo Packaging
```

### Milestone Summary
* **Phase 1:** Core project contracts, `FlowRecord`, `DNSRecord`, `TLSMetadataRecord`, and zero-copy packet parser.
* **Phase 2:** Welford algorithm, rolling ring buffers (1s, 10s, 60s), Shannon entropy, and 22-dimensional feature vector extraction.
* **Phase 3:** Benign and attack traffic scripts; 7 curated PCAP benchmark fixtures with ground-truth manifests.
* **Phase 4A:** Fast-Path rule arbiter evaluating in $< 0.2\text{ ms}$; non-ML baseline performance report.
* **Phase 4B:** 4 specialized LightGBM classifiers; Isotonic calibration; TreeSHAP top-3 feature attribution.
* **Phase 5A & 5B:** FastAPI monolith with SQLite WAL persistence, 30s alert deduplication cache, and live SSE streaming.
* **Phase 6:** React 18 + Vite + Tailwind CSS dark-mode dashboard with 60 FPS virtualized table, Recharts, and replay scrubber.
* **Phase 7:** Zero-egress network namespace verification, automated benchmark harness ($\ge 20,000\text{ flows/sec}$), and offline demo packaging.

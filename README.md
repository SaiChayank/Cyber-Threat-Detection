# PS26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> **National Technical Research Organisation (NTRO) / Smart India Hackathon**  
> *Theme: Blockchain & Cybersecurity*  
> *Status: Active Development (100% Free & Open-Source)*

---

## 1. Project Overview

**PS26145** is an AI/ML and rule-based threat detection pipeline designed to passively ingest a **unidirectional stream of IP network traffic** (e.g., from an optical data diode or mirror port) and detect, classify, and score cyber-security threats in near real-time without ever transmitting any packets back into the source network.

### Key Constraints & Architecture
* **Strictly Passive / No Return Path:** The ingestion link never sends probes, performs handshakes, sends RST packets, or pushes inline blocks.
* **No Payload Decryption:** All TLS 1.3/QUIC traffic is analyzed solely via handshake metadata (`JA3`, `JA3S`, `JA4`, `SNI`) and packet dynamics (inter-arrival times, packet-size sequences).
* **Streaming & Bounded Latency:** Continuous stream processing with target throughput $\ge 2,000\text{ flows/sec}$ and $\text{p95 alert latency} < 2\text{s}$.
* **Hybrid Detection:** Fast rule-based heuristics combined with calibrated machine learning classifiers (Random Forest, XGBoost, Logistic Regression).
* **Zero Train/Serve Skew:** Replays captured experiments through the **exact same** streaming and feature computation code path as live inference.

---

## 2. Monitored Threat Categories

| Category | Primary Engine | Corroborating Model | Key Features |
| :--- | :--- | :--- | :--- |
| **DDoS (SYN / Volumetric / Spoofed)** | Rule Engine | Random Forest | Packet/byte rates, SYN-no-completion ratio, IP entropy (Count-Min Sketch) |
| **Botnet C2 Beaconing** | Classifier | Random Forest / XGBoost | Inter-arrival timing regularity (Welford CV), size consistency, destination repeat counts |
| **DGA Domains** | Classifier | Random Forest / XGBoost | Character entropy, character n-gram frequencies, NXDOMAIN burst ratios |
| **DNS Tunnelling** | Classifier | Random Forest | Query length distribution, TXT/NULL record concentration, response size ratios |
| **Encrypted-Session Malware** | Rule Engine | *Documented Future Work* | Curated JA3 blocklist matching + session packet-size/timing variance |
| **Reconnaissance / Port Scanning** | Rule Engine | Logistic Regression | Host & port fan-out tracking (HyperLogLog), scan attempt rates |
| **Data Exfiltration** | Classifier | Random Forest / XGBoost | Outbound:inbound byte ratio asymmetry, cumulative volume, destination novelty (Bloom filter) |

---

## 3. Repository Structure

```
ps26145/
├── ingest/         # Passive capture, PCAP parsing, dead-letter routing
├── schemas/        # Canonical FlowRecord, DNSRecord, TLSQUICMetadata, and Alert schemas
├── streaming/      # Stream normalizer, watermarking, state store (Welford, HyperLogLog, CMS)
├── features/       # Modular causal feature extractors per threat class
├── detection/      # Rule detectors, ML inference wrappers, severity scoring, and dedup
├── ml/             # Experiment dataset assembly, temporal splits, model training & calibration
├── alerts/         # Alert object assembly, deterministic explanations, Redis publisher
├── backend/        # FastAPI modular monolith, SSE live broadcast, REST endpoints
├── persistence/    # SQLAlchemy models, SQLite/PostgreSQL storage, audit logging
├── frontend/       # React + Vite + TypeScript + Tailwind CSS SOC analyst dashboard
├── replay/         # Experiment archive replay engine (real-time and accelerated)
├── benchmarks/     # Automated throughput (flows/sec) and latency benchmark harness
├── tests/          # Unit, integration, security, and architectural-compliance test suites
├── deployment/     # Docker Compose lab definitions, fake-DNS resolver, generator configs
└── docs/           # Authoritative design specifications, audits, and master blueprint
```

---

## 4. Quickstart Guide (100% Free & Local)

### Prerequisites
* **Python 3.11+**
* **Node.js 18+ & npm**
* Git

### Step 1: Clone & Python Virtual Environment
```bash
git clone <your-github-repo-url>
cd PS26145

# Create & activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(By default, `USE_FAKEREDIS=true` enables pure-Python in-memory Redis Streams, requiring zero external server installations!)*

### Step 3: Run the Backend
```bash
uvicorn backend.main:app --reload --port 8000
```
API Documentation will be accessible at: `http://localhost:8000/docs`  
Health check endpoint: `http://localhost:8000/api/health`

### Step 4: Run the Frontend SOC Dashboard
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
Dashboard will be accessible at: `http://localhost:5173`

### Step 5: Run the Verification Tests
```bash
pytest tests/
```

---

## 5. Verification & Architectural Compliance

PS26145 enforces 6 zero-tolerance architectural compliance checks in `tests/`:
1. **No-Return-Path Proof:** Verification that the capture interface has no assigned IP address and no egress routing.
2. **Zero In-Band Probing:** Assertion that no packets are transmitted out of the capture NIC.
3. **No Inline Blocking:** Verification that traffic flows unobstructed without inline proxy interception.
4. **No Payload Decryption:** TLS inspection operates strictly on unencrypted ClientHello/ServerHello metadata and packet dynamics.
5. **Incremental Streaming:** Alert latency remains bounded without batch-delay accumulation.
6. **Pre-Completion Alerting:** Long-running attacks trigger alerts *before* session termination.

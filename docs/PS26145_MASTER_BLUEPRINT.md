# PS26145 — FINAL IMPLEMENTATION BLUEPRINT
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Status: Implementation Source of Truth.** Consolidates every approved decision from prior design tasks. No prior research is repeated except where needed for a self-contained reading; no settled choice is revisited except where a contradiction required a ruling (already resolved in the second final audit). No source code is generated here.

**Labeling convention used throughout:**
- 🔵 **OFFICIAL** — stated or directly implied by the SIH listing text itself; non-negotiable.
- 🟢 **APPROVED** — a project design decision made and frozen across prior tasks.
- 🟡 **ASSUMPTION/LIMITATION** — a stated constraint, gap, or simplification the team has consciously accepted.

---

## 1. Final Project Definition

🔵 **OFFICIAL:** Design and build an AI/ML pipeline that ingests a one-directional (simulated) IP traffic stream and detects, classifies, and scores six named cyber-threat categories in near real time, using only passively collected data (packet captures, NetFlow/IPFIX/sFlow, derived metadata), for NTRO under the Blockchain & Cybersecurity theme. The detector can never re-contact a source/destination, complete a handshake, or push any action back across the ingest path. Output is labelled alerts with confidence, evidence, and a live/replayed dashboard.

🟢 **APPROVED:** The seven-way threat breakdown used throughout this project (splitting the SIH's combined "DGA/DNS tunnelling" category into two detectors) is retained, since it does not change official scope, only implementation granularity.

🟡 **LIMITATION:** Encrypted-session malware ships as a **rule-based detector only** for this prototype; its ML classifier is documented future work pending a resolved training-data source (capability-classification decision, ratified in the second final audit).

---

## 2. Requirement Traceability (Summary)

Every official requirement has a confirmed implementation path (full detail in §E):

| Requirement | Status |
|---|---|
| Six named threat categories (seven-way internal breakdown) | 🟢 Six full hybrid, one rule-only (disclosed) |
| Passive, read-only, no return path, no active probing, no handshake, no inline mitigation | 🟢 Fully designed and test-gated |
| No TLS/QUIC payload decryption | 🟢 Fully designed and test-gated |
| Streaming, bounded-latency, incremental processing | 🟢 Fully designed and test-gated |
| Demonstrated throughput | 🟡 Target committed (≥2,000 flows/sec); **not yet empirically measured** — Phase 14 closes this |
| Structured alert schema (timestamp, flow ID, threat class, confidence, evidence) | 🟢 Fully designed |
| Working prototype + documentation of models/features/training | 🟢 This blueprint plus the full design-task archive in `docs/` |
| Dashboard, live or replayed, severity + confidence | 🟢 Fully designed |

---

## 3. MVP Scope

🟢 **APPROVED (capability-classification task, ratified in final audit):**
- **Build:** all Tier-1/Tier-2 items (seven-threat detection with the rule-only exception above, full runtime pipeline, alert schema, backend, four MVP dashboard pages, replay mode, throughput demonstration, MVP security controls, model/dataset integrity hashing), calibrated confidence, analyst feedback (cheap, already designed), a lightweight tamper-evident alert hash-chain.
- **Do not build:** anomaly detection (Isolation Forest), SHAP explanations, pluggable-detector framework, incident correlation, threat timelines, deep sequence models (GRU/Temporal CNN/char-CNN), online learning, horizontal scaling, RBAC, rate limiting, container hardening beyond basic hygiene, full API abuse protection.
- **Two strategic calls:** encrypted-session malware descoped to rule-only; DGA traffic-generation script closed quickly (small, high-value fix, not descoped).

---

## 4. Final System Architecture

```
┌─────────────────────────────── LAB (Docker Compose, single host) ───────────────────────────────┐
│  benign-generator   attack-simulator   victim   c2-tunnel-endpoint   capture (no IP, promiscuous) │
└───────────────────────────────────────┬────────────────────────────────────────────────────────┘
                                         │ mirrored traffic (one direction only)
                          ┌──────────────▼───────────────┐
                          │   RUNTIME PIPELINE (asyncio)  │   Redis Streams = ingest buffer + alert bus
                          │  Ingest→Parser→Normalizer→    │
                          │  Streaming State→Features→    │
                          │  Detection(Rules+ML)→Conf/Sev │
                          │  →Evidence→Alert Output       │
                          └──────────────┬────────────────┘
                                         │ Redis Stream (alerts)
                          ┌──────────────▼────────────────┐
                          │  BACKEND (FastAPI, modular     │  SQLite (prototype) → Postgres (production)
                          │  monolith) — Ingestion Adapter,│
                          │  Alerts/Replay/Models/Metrics/ │
                          │  Feedback/Audit modules, SSE   │
                          └──────────────┬────────────────┘
                                         │ REST + SSE
                          ┌──────────────▼────────────────┐
                          │  SOC DASHBOARD (React/Vite)    │
                          └─────────────────────────────────┘
```
🟢 **APPROVED:** modular monolith, no microservices; single-host Docker Compose lab supersedes the original multi-VM design for what's actually built.

---

## 5. Runtime Data Flow

🔵/🟢 Ten-stage flow: `Traffic/Replay → Passive Ingest → Parser → Normalizer → Streaming State → Feature Extraction → Detection → Confidence/Severity → Evidence → Alert Output`.
- **LIVE/SIMULATED MODE:** reads the mirror NIC in real time, generator-paced.
- **REPLAY MODE:** reads archived experiment data, real-time-paced or accelerated; **same code path as live** (this is also the mechanism that structurally resolves the train/serve feature-computation skew — see §8).
- Backpressure propagates backward but never reaches Passive Ingest (no return-path to a real network link); overflow there triggers explicit, logged load-shedding (drop-oldest).
- Three distinct drop categories (capture-level, overflow, late-arrival) logged separately.

---

## 6. Data and Dataset Architecture

🔵 **Official tools:** benign — iperf3, Ostinato, TRex. Attack — hping3, Slowloris (folded into DDoS class), dnscat2, iodine, DGArchive/published algorithms, a sandboxed C2 emulator (🟡 specific tool still unselected — Phase 3 blocker).
🟢 **Supplementary, validation-only, never blended into training:** CIC-DDoS2019 (attack-side), CTU-13, CIRA-CIC-DoHBrw-2020.
🟢 **Lab topology:** single-host Docker Compose, two networks (`internal`, no egress; `control`, orchestration-only), capture container with no IP, promiscuous only.
🟢 **Canonical schema:** `FlowRecord` (universal), `DNSRecord`, `TLSQUICMetadata` (linked, populated only when relevant) — PCAP is the only source format that populates every field; NetFlow/IPFIX/sFlow lack DNS/TLS metadata and raw sequences (🟡 hard dependency, no fallback if capture ever degrades to flow-only).
🟢 **Storage:** `raw_pcap/`, `flows/`, `labels/`, `metadata/`, `index/` per experiment ID.

---

## 7. Feature Architecture

🟢 Causal-only features (never use data timestamped after the current event); static reference tables (n-gram model, JA3 blocklist) built only from pre-evaluation data.

| Detector | Key features |
|---|---|
| DDoS | packet/byte rate, SYN-no-completion ratio, source-IP entropy, TTL variance, unique-source count |
| C2 Beaconing | inter-arrival mean/variance, periodicity score, destination repeat count, flow-size consistency |
| DGA | domain char entropy, n-gram score, domain length, NXDOMAIN ratio, query rate |
| DNS Tunnelling | query length avg/max, record-type distribution, response size, query concentration |
| Encrypted Malware | JA3/JA3S/JA4, rarity score, packet-size/timing prefix stats, SNI presence |
| Reconnaissance | unique dst-port/host fan-out, scan rate, flow-completion ratio |
| Exfiltration | outbound:inbound byte ratio, cumulative outbound volume, destination novelty, baseline deviation |

🟢 **Online-computation primitives:** Welford (exact mean/variance), EWMA (long-horizon baselines), HyperLogLog (unbounded-space cardinality), Count-Min Sketch (frequency/entropy), Bloom filter (novelty checks), exact bitmap (bounded spaces like ports). 🟢 **Use existing libraries** (e.g., `datasketch`, `probables`) — do not hand-roll (final-audit complexity finding).
🟢 Missing/duplicate/out-of-order handling: null (never zero) on missing fields, completeness flag per window; composite-key dedup; watermark + bounded allowed-lateness for late arrivals; sufficient-statistics-only state for long windows with inactive-key eviction.

---

## 8. Detection and ML Architecture

🟢 **Hybrid architecture:** rules remain the first-pass detector for every threat; classifiers add value only where rules were shown to fall short.

| Detector | Primary | MVP Model |
|---|---|---|
| DDoS | Rule | + Random Forest corroboration |
| Reconnaissance | Rule | + Logistic Regression corroboration |
| C2 Beaconing | Classifier | Random Forest/XGBoost on engineered features |
| DGA | Classifier | Random Forest/XGBoost (lexical + host-behavioral) |
| DNS Tunnelling | Classifier | Random Forest |
| Data Exfiltration | Classifier | Random Forest/XGBoost |
| Encrypted Malware | Rule **only** (MVP) | Blocklist + two-variance heuristic; ML classifier is future work |

🟢 **Confidence:** ML scores calibrated (Platt/isotonic, fit on validation split only); rule-only alerts use staged confidence values; hybrid combination = max of both.
🟢 **Severity ≠ confidence** (kept structurally separate fields): `severity = base_weight(threat) × confidence_tier × magnitude_factor`. 🟡 Base weights are team-authored constants, not empirically derived — stated plainly, not oversold.
🟢 **Training/eval methodology:** experiment-level (not flow-level) train/val/test split; temporal walk-forward preference; configuration holdout tested separately from temporal holdout; class weighting for imbalance; macro F1/PR-AUC/FPR as primary metrics, never accuracy alone (a trivial "always benign" classifier would score high accuracy while catching nothing).
🟢 **Ruling (final audit):** training-data feature computation reuses the **same** `replay → ingest → streaming → features` modules as live inference — no separate offline batch tool. This eliminates train/serve skew by construction.
🟡 **Team targets (not SIH-mandated):** Macro F1 ≥ 0.70, per-class recall ≥ 0.65, tiered FPR budgets, PR-AUC ≥ 0.70, ECE ≤ 0.15 (MVP stage).

---

## 9. Streaming Architecture

🟢 **Stack:** Python `asyncio` (in-process pipeline core) + Redis Streams (ingest buffer, alert bus) — chosen over ZeroMQ (no built-in persistence/backpressure), NATS/Kafka (disproportionate operational cost for this scale).
🟢 Bounded queues at every stage boundary; per-key ordering via routing (no global sequencer); watermarking with bounded allowed lateness; per-detector failure isolation (one failing detector never blocks others).
🟡 Redis Streams → Kafka is a documented, not implemented, upgrade path if real scale ever demands it.

---

## 10. Alert and Evidence Architecture

🔵 **Official fields:** `timestamp`, `flow_id`, `threat_class`, `confidence`, `supporting_evidence`.
🟢 **Derived required fields:** `alert_id`, `detection_timestamp`, `detector_type`, `model_version`, `severity`, `src/dst_ip/port`, `protocol`, `explanation`, `sub_type`, `completeness_flag`.
🟢 **Optional fields:** `correlation_id` (reserved, unused), `raw_feature_snapshot`, `analyst_feedback`, `experiment_id`.
🟢 **Explanations are template-based, never LLM-generated for MVP** — a template can only insert already-verified evidence values, never fabricate one.
🟢 **Deduplication:** key = `(threat_class, primary_entity_key, time_bucket)`; cooldown suppression with severity-escalation override; rule+ML dual-fire = one hybrid alert.
🟢 **Correlation explicitly deferred** — schema reserves the field, nothing more.

---

## 11. Backend, Database, and APIs

🟢 **Framework:** FastAPI, single modular monolith (Ingestion Adapter, Alerts, Live Broadcast, Replay, Model Registry, Metrics, Feedback, Audit modules) — no microservices.
🟢 **Entities:** `alerts`, `replay_sessions`, `model_versions`, `system_metrics`, `analyst_feedback`, `audit_events`, with FK relationships and composite indexes (`threat_class, dst_ip, timestamp`, `severity`, `model_version_id`, `replay_session_id`).
🟡 **Not yet implemented:** model/dataset integrity hash columns and specific `audit_events` types were security-review MVP items, still prose-only as of the last audit — Phase 12 closes this.
🟢 **Minimum API set:** `/api/alerts/current`, `/api/alerts/stream` (SSE), `/api/alerts/{id}`, `/api/alerts/history` (+filters), `/api/replay/sessions` (POST/GET), `/api/analytics/summary`, `/api/health`, `/api/metrics/throughput`, `/api/models`(+detail), `/api/alerts/{id}/feedback`.
🟢 **SSE, not WebSocket** — the data flow is one-directional; WebSocket's duplex capability is unneeded complexity here.
🟢 **Storage:** SQLite (prototype) → PostgreSQL (production, least-privilege role).

---

## 12. SOC Dashboard

🟢 **MVP pages:** Overview (with compact throughput/latency widget), Live Detections (SSE-driven), Alerts (historical/filtered), Alert Detail (per-threat evidence visualizations).
🟢 **High-value:** Replay, Threat Analytics (🟡 its aggregate visualizations depend on an `/api/analytics/summary` extension not yet designed — Phase 9 task).
🟢 **Future:** System Performance (dedicated page); Overview's widget covers the official throughput requirement in the meantime.
🟢 **Stack:** React + Vite + TypeScript, TailwindCSS, Recharts, native `EventSource` — no Next.js/SSR (unneeded for an internal dashboard).

---

## 13. Security

🟢 **MVP:** authentication (single shared token), coarse write-endpoint authorization, CORS allow-list, request-size/timeout limits, input validation (Pydantic), file/PCAP validation (manifest-checked experiment IDs, structural pcap checks), secrets via environment variables, dependency scanning (`pip-audit`/`npm audit`), model/dataset integrity hashing, audit logging.
🟢 **Recommended (build if time allows):** RBAC, rate limiting, lightweight tamper-evident alert hash-chain, container hardening.
🟢 **Production-only:** full API abuse protection, hardened container policy, PostgreSQL least-privilege role.
🔵/🟢 **Passive-ingest guardrail (non-negotiable):** capture interface never gets an IP; file/PCAP validation stays purely structural (no external malware-scan calls); no DNS/domain evidence enrichment ever performs a live resolution — verified by running capture in a network namespace with all egress blocked. 🟡 Docker lateral-reachability (capture container to other same-host services) has not been explicitly verified — a narrower gap than the egress test covers (skeptical-review Issue 15).

---

## 14. Testing and Evaluation

🟢 Full suite designed: unit (parsers/features/detectors), ML (validation gate, false-positive suite against named benign patterns, temporal-leakage checks), integration (golden-file, dedup, hybrid-combination), system (backend/DB/dashboard/replay), security (execution checklist), and six zero-tolerance architectural-compliance tests (no probe, no return path, no inline blocking, no decryption, incremental processing, pre-completion alerting).
🟡 **Not yet executed:** the passive-ingest no-egress test and the throughput/latency benchmark — both specified, neither run as of this blueprint.
🟢 MVP acceptance criteria are a hard multi-gate checklist (any single failure blocks acceptance).

---

## 15. Performance Benchmarking

🟡 **Committed target (team-set, not SIH-mandated, NOT YET MEASURED):** ≥2,000 flows/sec, p95 end-to-end alert latency < 2 seconds, no unbounded queue growth, stable memory over a one-hour run.
🔵 Official requirement is only that *a* throughput figure be stated and demonstrated — the specific number is a team choice.
🟢 Method: accelerated-replay load generator, latency measured per stage boundary (feature/inference/end-to-end), queue depth and drop-type sampling, CPU/memory profiling over a sustained run.
🟡 **No documented capacity estimate ties this number to the chosen asyncio+Redis stack** — Phase 14 must run the real benchmark and report the actual figure, adjusting the demo claim if it differs.

---

## 16. Deployment

🟢 **Local dev:** native processes, one Redis instance, SQLite, fixture pcaps for fast iteration, no lab required.
🟢 **Hackathon deployment:** single-host Docker Compose (10 services: benign-generator, attack-simulator, victim, c2-tunnel-endpoint, capture, redis, pipeline, backend, db-volume, frontend), two internal-only networks, no internet dependency at runtime, offline-capable.
🟢 **Production (optional, documented only):** real hardware data diode/SPAN port, PostgreSQL with least-privilege role, dedicated time-series store for metrics, Redis Streams → Kafka upgrade path, multi-host separation.

---

## 17. Repository Structure

```
ps26145/
├── ingest/        # Passive Ingest + Parser (per-format)
├── schemas/       # Canonical FlowRecord/DNSRecord/TLSQUICMetadata + alert schema
├── streaming/     # Normalizer + Streaming State (sketches/accumulators)
├── features/      # Per-threat feature computation
├── detection/     # Rules + ML wrappers + confidence/severity/evidence/dedup
├── ml/            # Training pipeline — reuses replay/ingest/streaming/features (no separate batch tool)
├── alerts/        # Alert Output — object assembly + Redis publish
├── backend/       # FastAPI app, routers, SSE, Ingestion Adapter
├── persistence/   # DB models, migrations
├── frontend/      # React dashboard
├── replay/        # Archive reader, pacing, session lifecycle
├── benchmarks/    # Load generation, latency/queue/CPU/memory measurement
├── tests/         # Unit/ML/integration/system/security/architectural-compliance
├── deployment/    # Dockerfiles, compose variants, lab configs
└── docs/          # This blueprint + full design-task archive
```

---

## 18. Phase-by-Phase Implementation Roadmap

> Every phase ends with a **Verification Gate**. Do not proceed until it passes.

### Phase 1 — Environment & Repository Bootstrap
1. **Objective:** A working, empty-but-structured repo any teammate can clone and run.
2. **Exact tasks:** Create the repo-structure directories (§17); initialize Python project (`pyproject.toml`/`requirements.txt`) and frontend project (Vite + React + TS); set up `.env.example`/`.gitignore`; install Redis locally.
3. **Subtasks:** pin Python/Node versions; add `pytest` scaffold; add `pip-audit`/`npm audit` as manual pre-commit checks.
4. **Technologies:** Python 3.11+, Node/Vite, Redis, git.
5. **Dependencies/prerequisites:** none — this is the first phase.
6. **Files/modules:** root `pyproject.toml`, `frontend/package.json`, `.env.example`, `.gitignore`, empty package `__init__.py` files per directory.
7. **Expected deliverables:** a runnable "hello world" FastAPI endpoint and a Vite dev-server page, both starting without error.
8. **Tests/validation:** `pytest` runs (even with zero tests) without import errors; `npm run dev` serves a page.
9. **Definition of Done:** fresh clone + documented setup steps → both processes start locally with no manual fixes.
10. **Key risks/mitigations:** environment drift across teammates' machines — mitigate by pinning exact versions in `pyproject.toml`/`package.json`.
11. **Next-phase dependency:** Phase 2 needs the `schemas/` package skeleton to exist.

**✅ Verification Gate 1:** repo clones clean; both dev servers start; `pytest`/`npm audit` run without configuration errors.

---

### Phase 2 — Canonical Schemas
1. **Objective:** Freeze the data contracts every other phase depends on.
2. **Exact tasks:** Implement `FlowRecord`, `DNSRecord`, `TLSQUICMetadata` (Pydantic/dataclasses per §6); implement the final alert schema (§10) with official/derived/optional fields and enums (`threat_class`, `severity`, `detector_type`).
3. **Subtasks:** write field-level docstrings referencing the source design tasks; add serialization round-trip tests.
4. **Technologies:** Pydantic (or dataclasses), Python `enum`.
5. **Dependencies/prerequisites:** Phase 1.
6. **Files/modules:** `schemas/flow_record.py`, `schemas/dns_record.py`, `schemas/tls_quic_metadata.py`, `schemas/alert.py`, `schemas/enums.py`.
7. **Expected deliverables:** importable, fully-typed schema package with no other module dependencies.
8. **Tests/validation:** unit tests instantiate each schema with valid/invalid data, confirming validation errors fire correctly (nullable fields, enum constraints).
9. **Definition of Done:** 100% of fields from §6/§10 represented; schema unit tests pass.
10. **Key risks/mitigations:** schema churn later — mitigate by treating this phase's output as frozen; any change after Phase 5 requires a documented migration note.
11. **Next-phase dependency:** Phase 3 (lab) needs the alert/flow schemas only conceptually; Phase 4 (ingest) needs them directly.

**✅ Verification Gate 2:** all schema unit tests pass; no downstream phase has started importing from anywhere except `schemas/`.

---

### Phase 3 — Synthetic Traffic Lab
1. **Objective:** A running, isolated, single-host lab producing labeled traffic.
2. **Exact tasks:** Write Docker Compose services (`benign-generator`, `attack-simulator`, `victim`, `c2-tunnel-endpoint`, `capture`) per §6/§16; configure the two internal-only networks; **select the specific sandboxed C2 emulator tool** (open decision, blocking); write the DGA domain-list-to-DNS-traffic script (previously flagged, closing skeptical-review Issue 18); confirm DGArchive access/licensing (closing Issue 9), substituting an alternate published DGA source if blocked.
3. **Subtasks:** configure the internal fake-DNS resolver zone; write the experiment manifest writer (experiment ID, labels, timestamps, hashes per Phase 12's integrity requirement).
4. **Technologies:** Docker Compose, iperf3/Ostinato/TRex, hping3/Slowloris, dnscat2/iodine, the selected C2 emulator, DGArchive or substitute.
5. **Dependencies/prerequisites:** Phase 1.
6. **Files/modules:** `deployment/docker-compose.dev.yml`, `deployment/lab/*` (configs, DGA script), `replay/` archive-writer stub (used to record experiments).
7. **Expected deliverables:** `docker compose up` produces a running lab; a labeled benign + one labeled attack experiment (e.g., DDoS) captured and stored per §6's directory structure.
8. **Tests/validation:** manual capture inspection (packet counts, correct labels); confirm the capture interface has no IP (`ip addr` check).
9. **Definition of Done:** at least one full labeled experiment per threat class exists in the lab's storage structure, including a working DGA-traffic and C2-beacon run.
10. **Key risks/mitigations:** C2 emulator/DGArchive access risk (Issues 8/9) — resolve first, before building anything downstream that assumes their output shape.
11. **Next-phase dependency:** Phase 4 needs real captured pcap/flow files to parse against.

**✅ Verification Gate 3:** all seven threats have at least one successfully captured, labeled experiment; capture interface confirmed IP-less.

---

### Phase 4 — Ingest, Parsing, Normalizer
1. **Objective:** Turn raw lab captures into canonical schema objects.
2. **Exact tasks:** Implement per-format parsers (PCAP required; NetFlow/IPFIX/sFlow stubs acceptable for MVP since the lab uses PCAP); implement malformed-record dead-letter handling; implement the Normalizer (format-specific → canonical schema).
3. **Subtasks:** implement the composite-key deduplication check at this stage.
4. **Technologies:** `scapy`/`pyshark`/`nfstream` (per original PS guidance) for PCAP parsing.
5. **Dependencies/prerequisites:** Phases 2, 3.
6. **Files/modules:** `ingest/pcap_parser.py`, `ingest/dead_letter.py`, `streaming/normalizer.py`.
7. **Expected deliverables:** a script that reads a Phase-3 capture file and emits a stream of canonical `FlowRecord`/`DNSRecord`/`TLSQUICMetadata` objects.
8. **Tests/validation:** unit tests per Phase 4's unit-test design (known-good samples, malformed-input handling, boundary cases) from the verification strategy.
9. **Definition of Done:** every Phase-3 experiment file parses into canonical objects with zero unhandled exceptions; malformed synthetic test files route to dead-letter.
10. **Key risks/mitigations:** parser edge cases (IPv6, zero-length payloads) — covered by the boundary-test set already designed.
11. **Next-phase dependency:** Phase 5 consumes this canonical stream directly.

**✅ Verification Gate 4:** parser unit tests pass; a full Phase-3 experiment parses end-to-end into canonical records.

---

### Phase 5 — Streaming State & Feature Engineering
1. **Objective:** Compute the exact per-threat feature vectors from §7.
2. **Exact tasks:** Implement keyed state (Welford, EWMA, HyperLogLog, Count-Min Sketch, Bloom filter — via `datasketch`/`probables`, not hand-rolled); implement watermarking/allowed-lateness and window-expiry/inactive-key eviction; implement one feature module per threat.
3. **Subtasks:** implement the completeness flag; implement the static reference-table build process (DGA n-gram model, JA3 blocklist) with an explicit pre-cutoff timestamp check.
4. **Technologies:** `datasketch`, `probables`, NumPy for Welford/EWMA math.
5. **Dependencies/prerequisites:** Phase 4.
6. **Files/modules:** `streaming/state_store.py`, `streaming/sketches.py`, `features/ddos.py`, `features/c2.py`, `features/dga.py`, `features/dns_tunnelling.py`, `features/encrypted_malware.py`, `features/reconnaissance.py`, `features/exfiltration.py`.
7. **Expected deliverables:** for each Phase-3 experiment, the correct feature vector is produced and matches hand-computed expected values for at least one test case per threat.
8. **Tests/validation:** the full unit-test suite from the verification strategy (streaming-primitive correctness against known values, causality tests, window-expiry tests, high-cardinality bound tests).
9. **Definition of Done:** all feature unit tests pass; causality test confirms no look-ahead; memory-bound test confirms no unbounded growth under a high-cardinality synthetic load.
10. **Key risks/mitigations:** sketch library API mismatches with the designed error bounds — validate empirically in the unit tests, don't assume defaults are correct.
11. **Next-phase dependency:** Phase 6 (rules) and Phase 10 (ML) both consume this feature output.

**✅ Verification Gate 5:** all feature unit tests pass, including causality and memory-bound tests.

---

### Phase 6 — Rule-Based Detectors + Alert Output (Rule Path)
1. **Objective:** A fully working rule-only detection path for all seven threats, including the encrypted-malware blocklist detector.
2. **Exact tasks:** Implement one rule module per threat per the rule-baseline thresholds; implement severity calculation, template-based explanation generation, and the alert object builder; implement deduplication/cooldown logic; implement the Redis publish client.
3. **Subtasks:** curate the encrypted-malware JA3 blocklist (including the pinned demo fingerprint, closing skeptical-review Issue 19 early); write the per-threat explanation templates with boundary-value tests (closing Issue 12).
4. **Technologies:** pure Python, Redis client.
5. **Dependencies/prerequisites:** Phase 5.
6. **Files/modules:** `detection/rules/*.py` (one per threat), `detection/severity.py`, `detection/explanations.py`, `detection/dedup.py`, `alerts/builder.py`, `alerts/publisher.py`.
7. **Expected deliverables:** running the Phase-3 experiments through Phases 4–6 produces correctly-classified alerts for all seven threats via rules alone, published to Redis.
8. **Tests/validation:** rule-threshold boundary tests; integration golden-file test (Phase-3 fixture → expected alert); explanation-template boundary tests.
9. **Definition of Done:** every threat scenario from the verification strategy's test-scenario table (§8 of that document) produces the expected alert via the rule path; every paired benign scenario produces none.
10. **Key risks/mitigations:** rule thresholds mis-tuned against the specific lab hardware's traffic shape — recalibrate against Phase-3's actual captured benign/attack distributions, not the values documented abstractly.
11. **Next-phase dependency:** Phase 7 assembles this into the live/replay runtime.

**✅ Verification Gate 6 (major milestone):** all seven rule-only detectors correctly fire/don't-fire on their respective scenarios; a real alert object, matching the final schema, is published to Redis.

---

### Phase 7 — Runtime Pipeline Assembly
1. **Objective:** The full ten-stage pipeline running end-to-end, live and replay.
2. **Exact tasks:** Wire Phases 4–6 into one `asyncio` pipeline with bounded queues at each stage boundary; implement backpressure/load-shedding at ingest; implement the replay engine (real-time-paced and accelerated modes) and session lifecycle.
3. **Subtasks:** implement per-detector failure isolation (try/except per detector, health metric); implement the three distinct drop-type loggers.
4. **Technologies:** `asyncio`, `redis-py` (streams client).
5. **Dependencies/prerequisites:** Phase 6.
6. **Files/modules:** `streaming/pipeline.py` (orchestrator), `replay/engine.py`, `replay/session.py`.
7. **Expected deliverables:** `docker compose up` (lab) + running the pipeline against live capture produces alerts in Redis within the target latency; running it against a Phase-3 archive in both pacing modes produces the same alerts as the live run did.
8. **Tests/validation:** integration tests (malformed-event non-crash, dedup, detector-failure isolation); the six architectural-compliance tests (§14) run for the first time here — this is the natural point to prove no probe/no return path/no inline blocking/no decryption/incremental processing/pre-completion alerting.
9. **Definition of Done:** all six architectural-compliance tests pass; live and replay produce equivalent alerts for the same underlying scenario.
10. **Key risks/mitigations:** single-host resource contention under simultaneous load (skeptical-review Issue 7) — stress-test with all lab containers + pipeline running concurrently before declaring this phase done, not just individually.
11. **Next-phase dependency:** Phase 8 (backend) consumes this pipeline's Redis alert stream.

**✅ Verification Gate 7 (major milestone):** all six architectural-compliance tests pass; a full rules-only live demo of any one threat is possible end-to-end.

---

### Phase 8 — Backend (API, Database, SSE)
1. **Objective:** A working FastAPI service serving the alert stream and history.
2. **Exact tasks:** Implement the six persistence entities and relationships/indexes (§11); implement the Ingestion Adapter (Redis consumer); implement the minimum API set; implement SSE broadcast.
3. **Subtasks:** implement authentication (single shared token) and CORS allow-list now, not later (cheap, foundational); implement input validation on every endpoint.
4. **Technologies:** FastAPI, SQLAlchemy, SQLite, `sse-starlette` or a native streaming response.
5. **Dependencies/prerequisites:** Phase 7 (needs real alerts flowing) and Phase 2 (schemas).
6. **Files/modules:** `persistence/models.py` (six entities), `backend/routers/*.py`, `backend/ingestion_adapter.py`, `backend/live_broadcast.py`, `backend/auth.py`.
7. **Expected deliverables:** alerts generated by Phase 7 appear in the database and are retrievable via `/api/alerts/history`; a connected SSE client receives them live.
8. **Tests/validation:** API contract tests, auth enforcement tests, referential-integrity tests, SSE delivery-delay test.
9. **Definition of Done:** every endpoint in §11's minimum set responds correctly against a seeded database; SSE test passes.
10. **Key risks/mitigations:** none beyond standard integration risk — this phase is mechanically straightforward given Phases 2 and 7 are solid.
11. **Next-phase dependency:** Phase 9 (dashboard) consumes this API/SSE surface.

**✅ Verification Gate 8:** all backend contract/auth/SSE tests pass.

---

### Phase 9 — SOC Dashboard (MVP)
1. **Objective:** The four MVP pages, functional against the real backend.
2. **Exact tasks:** Build Overview, Live Detections, Alerts, Alert Detail per the SOC-UI task's exact specs (components, filters, loading/empty/error states); implement the shared API client and severity/confidence UI components.
3. **Subtasks:** design and implement the `/api/analytics/summary` extension needed for Threat Analytics (closing the previously-flagged gap) if time allows in this phase, otherwise explicitly deferred to a documented follow-up, not silently dropped.
4. **Technologies:** React, Vite, TypeScript, TailwindCSS, Recharts, native `EventSource`.
5. **Dependencies/prerequisites:** Phase 8.
6. **Files/modules:** `frontend/src/pages/*.tsx`, `frontend/src/components/*.tsx`, `frontend/src/api/client.ts`.
7. **Expected deliverables:** a judge can open the dashboard, watch a live alert appear via SSE, and drill into its evidence.
8. **Tests/validation:** smoke tests per MVP page; state-rendering tests (loading/empty/error) per the SOC-UI task's explicit designs.
9. **Definition of Done:** all four MVP pages render correctly in all three states against the real backend; a live-triggered alert visibly appears without a manual refresh.
10. **Key risks/mitigations:** SSE reconnect behavior under a dropped connection — test explicitly, don't assume the browser's default `EventSource` reconnect is sufficient without verifying the "reconnecting…" UI state actually renders.
11. **Next-phase dependency:** Phase 10 (ML) can run in parallel with this phase, per the dependency graph (§19).

**✅ Verification Gate 9:** all four MVP pages pass their smoke and state-rendering tests against a live backend.

---

### Phase 10 — ML Dataset Assembly & Training
1. **Objective:** Trained, calibrated classifiers for the six classifier-primary detectors.
2. **Exact tasks:** Run all Phase-3 experiments through Phases 4–5 (via `replay/`) to assemble the training dataset — **per §8's ruling, this must go through the same `streaming/`/`features/` modules as live inference, never a separate batch tool**; implement experiment-level/temporal/scenario-separated splitting; train Random Forest/XGBoost per detector; fit calibration.
3. **Subtasks:** implement the model-registry writer (hash, metadata, version ID); run the ML validation suite (Macro F1, per-class P/R/F1, FPR, PR-AUC, calibration metrics) against MVP team targets.
4. **Technologies:** scikit-learn, XGBoost/LightGBM, a calibration library (e.g., scikit-learn's `CalibratedClassifierCV` for Platt/isotonic).
5. **Dependencies/prerequisites:** Phase 5 (features) and Phase 3 (enough labeled experiments per threat, including multiple configurations for the scenario-separation holdout).
6. **Files/modules:** `ml/dataset.py` (split logic), `ml/train_*.py` (one per detector), `ml/calibrate.py`, `ml/registry.py`.
7. **Expected deliverables:** one trained, calibrated, versioned model artifact per classifier-primary detector, meeting or explicitly falling short (documented) of MVP team targets.
8. **Tests/validation:** the ML validation gate, false-positive suite (named benign patterns), temporal-leakage automated checks (split-integrity, chronological-order, reference-table build-date).
9. **Definition of Done:** all six classifiers trained and calibrated; validation-gate results recorded (pass or documented shortfall) for both temporal and configuration holdouts.
10. **Key risks/mitigations:** insufficient labeled data volume/diversity from the lab (skeptical-review Issues 3, 20) — mitigate by using the supplementary validation datasets as an honesty check, not a training-data patch, and stating generalization caveats plainly rather than overselling metrics.
11. **Next-phase dependency:** Phase 11 integrates these models into the live detection layer.

**✅ Verification Gate 10:** the ML validation-gate report exists for all six classifiers, with pass/fail explicitly recorded against team targets — no silent gaps.

---

### Phase 11 — ML Integration into Detection (Hybrid)
1. **Objective:** Live detection now uses trained classifiers alongside rules.
2. **Exact tasks:** Implement the ML-detector wrapper (loads a versioned model from the registry); implement the model-integrity hash check at load time with rule-only fallback on mismatch; implement the max-confidence hybrid-combination logic where both rule and classifier fire.
3. **Subtasks:** wire `model_version` into every ML-derived alert.
4. **Technologies:** the trained artifacts from Phase 10, existing `detection/` module.
5. **Dependencies/prerequisites:** Phase 10 and Phase 7 (pipeline).
6. **Files/modules:** `detection/ml_wrapper.py`, `detection/hybrid_combiner.py`.
7. **Expected deliverables:** the six classifier-primary threats now produce ML-derived (or hybrid) alerts with calibrated confidence, not just rule-based staged confidence.
8. **Tests/validation:** hybrid-combination integration test; model-integrity tamper test (corrupt an artifact, confirm fallback to rule path).
9. **Definition of Done:** every classifier-primary threat's live/replay alert now carries `detector_type = ml` or `hybrid` with a real `model_version`; corruption test passes.
10. **Key risks/mitigations:** inference latency from six live models threatening the bounded-latency requirement — measure per-model latency now, not after Phase 14's benchmark surprises you.
11. **Next-phase dependency:** Phase 12 hardens security around this now-complete detection layer.

**✅ Verification Gate 11 (major milestone):** the full hybrid system — six ML-backed detectors plus one rule-only detector — is running end-to-end live and in replay.

---

### Phase 12 — Security Hardening
1. **Objective:** All MVP-classified security controls actually implemented, not just designed.
2. **Exact tasks:** Add the model-artifact and dataset-artifact hash columns to `model_versions` and the experiment manifest (closing the last audit's B1); implement the specific `audit_events` types and wire the audit hooks (auth failure, replay start, model-version change); run the dependency-security scan; run the passive-ingest no-egress test for the first time (closing the outstanding E2/E3 item); add the Docker lateral-reachability check (closing skeptical-review Issue 15).
3. **Subtasks:** build the lightweight tamper-evident alert hash-chain (recommended-tier, cheap, worth including).
4. **Technologies:** `pip-audit`/`npm audit`, network-namespace test tooling, Docker network-policy inspection.
5. **Dependencies/prerequisites:** Phase 11 (needs a complete system to secure).
6. **Files/modules:** `persistence/models.py` (schema addition), `backend/audit.py`, `tests/security/*`.
7. **Expected deliverables:** every MVP security control from the security-review task has a passing, executed test — not a documented intention.
8. **Tests/validation:** the full security execution checklist (§13/§14).
9. **Definition of Done:** every item in the security checklist passes; the no-egress and lateral-reachability tests both pass.
10. **Key risks/mitigations:** discovering a real gap late (e.g., lateral reachability actually fails) — budget time in this phase specifically for a fix cycle, not just a check-and-move-on pass.
11. **Next-phase dependency:** Phase 13 runs the full test suite against a now-secured system.

**✅ Verification Gate 12:** 100% of the MVP security checklist passes, including the two newly-added tests.

---

### Phase 13 — Testing & Verification Suite (Full Run)
1. **Objective:** Every test designed across this project's Verification Strategy actually executed once, end-to-end, against the complete system.
2. **Exact tasks:** Run the full unit, ML, integration, system, security, and architectural-compliance suites together (not per-phase in isolation); fix any regressions surfaced by running them together for the first time.
3. **Subtasks:** add the regression test guarding against future reintroduction of a second feature-computation implementation (closing the last audit's E1).
4. **Technologies:** `pytest`, CI script (even if run manually, not automated CI, given time constraints).
5. **Dependencies/prerequisites:** Phases 1–12 all complete.
6. **Files/modules:** `tests/` (already populated incrementally per-phase; this phase is the full-suite run and fix cycle).
7. **Expected deliverables:** a single test-run report showing pass/fail for every test category, with all failures resolved.
8. **Tests/validation:** this phase *is* the test-validation step.
9. **Definition of Done:** 100% pass rate across all designed tests, or an explicitly documented, judged-acceptable exception (never a silent skip).
10. **Key risks/mitigations:** integration surprises when running suites together for the first time — budget real fix time here, do not treat this as a formality.
11. **Next-phase dependency:** Phase 14 benchmarks a system already proven correct.

**✅ Verification Gate 13:** full test suite passes at 100%, or every exception is explicitly documented and justified.

---

### Phase 14 — Performance Benchmarking
1. **Objective:** Replace the asserted throughput/latency target with a real, measured number (closing skeptical-review Issue 6).
2. **Exact tasks:** Run the accelerated-replay load generator at increasing rates until queue depth grows unboundedly; record the actual sustained flows/sec and p95 end-to-end latency; run the one-hour memory-stability test; measure CPU under sustained load.
3. **Subtasks:** if the measured number falls short of the ≥2,000 flows/sec target, update every document/demo script that cites the target to cite the real number instead.
4. **Technologies:** `benchmarks/` load generator (built on `replay/`'s accelerated mode).
5. **Dependencies/prerequisites:** Phase 13 (a correctness-proven system is the only thing worth benchmarking).
6. **Files/modules:** `benchmarks/load_generator.py`, `benchmarks/report.py`.
7. **Expected deliverables:** a recorded benchmark report with real, reproducible numbers for flows/sec, Mbps, feature/inference/end-to-end latency percentiles, queue depth, drop counts, CPU, and memory.
8. **Tests/validation:** the report itself is the validation artifact; re-run once to confirm reproducibility.
9. **Definition of Done:** a benchmark report exists with real numbers; every demo/documentation reference to throughput/latency uses these numbers, not the original unmeasured target.
10. **Key risks/mitigations:** demo-hardware performance may differ from the benchmark machine — run the final benchmark on the actual demo hardware, not a development machine.
11. **Next-phase dependency:** Phase 15 packages the now-fully-measured system.

**✅ Verification Gate 14:** a real, reproducible benchmark report exists and is used to update every downstream claim.

---

### Phase 15 — Deployment Packaging
1. **Objective:** A judge or teammate can stand up the exact demo environment with one command.
2. **Exact tasks:** Finalize `docker-compose.hackathon.yml`; pre-build all images; write the `README.md`/quickstart in `docs/`; verify zero internet dependency at runtime.
3. **Subtasks:** confirm the demo hardware has all images cached locally before the event.
4. **Technologies:** Docker Compose.
5. **Dependencies/prerequisites:** Phase 14 (a benchmarked, tested system is what gets packaged).
6. **Files/modules:** `deployment/docker-compose.hackathon.yml`, `docs/README.md`.
7. **Expected deliverables:** `docker compose up` on the demo laptop, offline, produces the full running system.
8. **Tests/validation:** a full clean-machine dry run (ideally on a second laptop) confirming no hidden dependency was missed.
9. **Definition of Done:** two independent successful clean-environment startups (different machines if possible).
10. **Key risks/mitigations:** an untested dependency on the primary dev machine's local state — the clean-machine dry run is specifically designed to catch this.
11. **Next-phase dependency:** Phase 16 rehearses the demo against this exact packaged environment.

**✅ Verification Gate 15:** two independent clean-environment startups succeed.

---

### Phase 16 — Demo Rehearsal & Final Readiness
1. **Objective:** The 15-step demo (already fully designed) runs reliably, repeatedly, on the actual demo hardware.
2. **Exact tasks:** Rehearse all 15 steps at least three times per the demo-preparation checklist; time the full sequence; record the pre-recorded fallback video for each step; pin and verify the JA3-trigger client (closing skeptical-review Issue 19); confirm the DGA script step (Phase 3) is demo-ready or explicitly switch that step to replay-only.
3. **Subtasks:** rehearse the answers to the ten anticipated judge questions (§23/prior skeptical-review task) out loud, not just read them.
4. **Technologies:** none new — this phase exercises everything already built.
5. **Dependencies/prerequisites:** Phase 15.
6. **Files/modules:** none — rehearsal and fallback-recording only.
7. **Expected deliverables:** three consecutive successful full-sequence rehearsals; a complete set of fallback replay archives and screen-capture videos.
8. **Tests/validation:** the rehearsal itself; explicitly note any step's live reliability rate across the three runs.
9. **Definition of Done:** all 15 steps succeed live at least twice out of three rehearsals, with a validated fallback for every step regardless.
10. **Key risks/mitigations:** all risks catalogued in the skeptical-review task — this phase exists specifically to surface and fix what rehearsal reveals, not to discover it live.
11. **Next-phase dependency:** none — this is the final phase before judging.

**✅ Verification Gate 16 (final):** three rehearsals completed; fallback material exists for all 15 steps; the team can answer all ten anticipated judge questions confidently.

---

## 19. Phase Dependency Graph

```
1 → 2 → 3 → 4 → 5 → 6 → 7 ──┬─→ 8 → 9 ─────────┐
                             │                    ├─→ 12 → 13 → 14 → 15 → 16
                             └─→ 10 → 11 ─────────┘
```
- Phases 8–9 (backend/dashboard) and Phases 10–11 (ML training/integration) can run **in parallel** once Phase 7 is complete — both branches need the pipeline, neither needs the other.
- Phases 12 onward are strictly sequential and require both branches merged.

---

## 20. MVP vs Differentiators vs Future Enhancements

| Tier | Items |
|---|---|
| **MVP** | Seven-threat detection (six hybrid, one rule-only), full runtime pipeline, alert schema, backend, four dashboard pages, replay mode, throughput demo, MVP security, model/dataset integrity hashing, calibrated confidence, analyst feedback |
| **Differentiators** | Rule-vs-ML comparison narrative (already built into the architecture), lightweight tamper-evident alert hash-chain |
| **Future/Production** | Anomaly detection, SHAP, pluggable detectors, incident correlation, threat timelines, deep sequence models, online learning, horizontal scaling, RBAC, rate limiting, full container hardening, encrypted-malware ML classifier |

---

## 21. Risks and Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| ML metrics measured only on synthetic tool-generated traffic; real-world generalization unproven | Critical | State this caveat explicitly in all submission materials; never imply lab metrics represent real-world accuracy |
| Base-rate false-positive volume never computed in absolute terms | High | State FPR as a rate only; explicitly disclaim absolute volume was not estimated |
| Throughput/latency targets unmeasured until Phase 14 | High | Phase 14 exists specifically to close this before the demo |
| Encrypted-malware demo is a known-answer blocklist test | High | Disclose explicitly and confidently in the demo script (already done) |
| DGA script / C2 emulator / DGArchive licensing still open | Medium-High | All three resolved in Phase 3, first, before any downstream phase assumes their output |
| Single-host resource contention during live demo | Medium | Phase 7 and Phase 16 both stress-test under full simultaneous load |
| JA3 live-trigger fragility | Medium | Pin exact client/library version in Phase 16, verify in rehearsal |
| Docker lateral-reachability not verified | Medium | Closed explicitly in Phase 12 |
| Overall scope large for a student team | High | Phases are ordered so a rules-only, fully-demoable system exists after Phase 9 — a credible fallback submission even if Phases 10+ run out of time |

---

## 22. Final Technology Stack

Python 3.11+, `asyncio`, Redis Streams, FastAPI, SQLAlchemy, SQLite → PostgreSQL, `scapy`/`pyshark`/`nfstream`, scikit-learn, XGBoost/LightGBM, `datasketch`, `probables`, React + Vite + TypeScript, TailwindCSS, Recharts, native `EventSource`, Docker Compose, `pytest`, `pip-audit`/`npm audit`.

---

## 23. SIH Demonstration Plan

Reference: the full 15-step sequence, preparation checklist, fallback strategy, and anticipated-questions list are frozen in the prior demo-strategy task. Summary: system startup → passive ingest proof → benign baseline → six live-triggered threats (DDoS, DGA/tunnelling, reconnaissance, exfiltration) plus two replay-driven threats (C2 accelerated, encrypted-malware rule-only with explicit disclosure) → live-alert/confidence/severity/evidence walkthrough → historical replay → throughput → latency, each with a validated replay-based fallback.

---

## 24. Complete Development Checklist

- [ ] Repo bootstrapped, both dev servers run (Phase 1)
- [ ] Canonical schemas frozen and tested (Phase 2)
- [ ] Lab running; C2 emulator selected; DGA script built; DGArchive access confirmed; seven labeled experiments captured (Phase 3)
- [ ] Parsers/Normalizer pass all unit tests (Phase 4)
- [ ] All feature modules pass unit/causality/memory tests (Phase 5)
- [ ] All seven rule detectors fire correctly on golden-file fixtures (Phase 6)
- [ ] Full pipeline live+replay; all six architectural-compliance tests pass (Phase 7)
- [ ] Backend API/SSE/auth tests pass (Phase 8)
- [ ] Four MVP dashboard pages pass smoke/state tests (Phase 9)
- [ ] Six classifiers trained, calibrated, validated against team targets (Phase 10)
- [ ] Hybrid detection live; model-integrity fallback tested (Phase 11)
- [ ] Full security checklist passes, including no-egress and lateral-reachability tests (Phase 12)
- [ ] Full test suite passes at 100% or documented exception (Phase 13)
- [ ] Real benchmark report recorded; all claims updated to match (Phase 14)
- [ ] Two clean-environment startups succeed (Phase 15)
- [ ] Three rehearsals complete; all fallbacks ready; judge Q&A rehearsed (Phase 16)

---

## A. Exact Development Order

1. Environment & Repository Bootstrap
2. Canonical Schemas
3. Synthetic Traffic Lab
4. Ingest, Parsing, Normalizer
5. Streaming State & Feature Engineering
6. Rule-Based Detectors + Alert Output
7. Runtime Pipeline Assembly
8. Backend (API, Database, SSE)
9. SOC Dashboard (MVP)
10. ML Dataset Assembly & Training
11. ML Integration into Detection
12. Security Hardening
13. Testing & Verification Suite
14. Performance Benchmarking
15. Deployment Packaging
16. Demo Rehearsal & Final Readiness

*(Phases 8–9 and 10–11 may run in parallel per §19; all else is sequential.)*

---

## B. Phase 1 Starting Checklist (First Session)

- [ ] Create the repository and the fifteen top-level directories from §17.
- [ ] Initialize `pyproject.toml` with pinned Python version and core dependencies (FastAPI, Pydantic, `redis`, `pytest`).
- [ ] Initialize the frontend with `npm create vite@latest frontend -- --template react-ts`.
- [ ] Install and start a local Redis instance.
- [ ] Create `.env.example` and `.gitignore` (excluding `.env`, `__pycache__`, `node_modules`, local SQLite files).
- [ ] Write one trivial FastAPI health endpoint and confirm it starts.
- [ ] Confirm `npm run dev` serves a blank page without error.
- [ ] Commit this skeleton as the first commit.

---

## C. One Compact Implementation Prompt Per Phase

1. *"Set up a Python + Redis + React/Vite/TypeScript project skeleton per the PS26145 repository structure (`ingest/ schemas/ streaming/ features/ detection/ ml/ alerts/ backend/ persistence/ frontend/ replay/ benchmarks/ tests/ deployment/ docs/`), with a working FastAPI health endpoint and a blank Vite dev page. No detection logic yet."*
2. *"Implement the PS26145 canonical schema package in `schemas/`: `FlowRecord`, `DNSRecord`, `TLSQUICMetadata`, and the final alert schema, with official/derived-required/optional fields as specified, using Pydantic. Include validation unit tests."*
3. *"Write Docker Compose services for the PS26145 single-host lab: benign-generator (iperf3/Ostinato/TRex), attack-simulator (hping3/Slowloris/dnscat2/iodine/DGA-query-script/C2-client/scan-tool/exfil-script), victim, c2-tunnel-endpoint, and a no-IP promiscuous capture container, on two internal-only Docker networks. Include an experiment manifest writer."*
4. *"Implement PCAP parsing and a Normalizer in `ingest/`/`streaming/` that convert raw packets into the PS26145 canonical `FlowRecord`/`DNSRecord`/`TLSQUICMetadata` schema, with malformed-record dead-letter handling and composite-key deduplication."*
5. *"Implement causal streaming feature computation in `streaming/`/`features/` for PS26145's seven threats, using `datasketch`/`probables` for HyperLogLog/Count-Min/Bloom-filter primitives and hand-written Welford/EWMA accumulators. Include window-expiry, watermarking, and completeness-flag logic."*
6. *"Implement rule-based detectors for all seven PS26145 threats in `detection/rules/`, plus severity scoring, template-based explanation generation, deduplication, and alert publishing to Redis Streams, matching the frozen alert schema."*
7. *"Assemble the PS26145 runtime pipeline in `streaming/pipeline.py`: wire ingest→parser→normalizer→streaming-state→features→detection→confidence/severity→evidence→alert-output into one asyncio pipeline with bounded queues, backpressure, and per-detector failure isolation. Implement live and replay (real-time-paced and accelerated) modes."*
8. *"Build a FastAPI backend for PS26145 with the six entities (alerts, replay_sessions, model_versions, system_metrics, analyst_feedback, audit_events), the minimum API set, SSE live-alert streaming, and a Redis Streams consumer that persists and broadcasts incoming alerts."*
9. *"Build the PS26145 SOC dashboard MVP pages (Overview, Live Detections, Alerts, Alert Detail) in React/Vite/TypeScript/Tailwind/Recharts, consuming the backend's REST+SSE API, with loading/empty/error states as specified."*
10. *"Assemble a labeled training dataset for PS26145's six classifier-primary detectors by replaying lab experiments through the existing `streaming`/`features` modules (not a separate batch tool), split by experiment ID with temporal and configuration holdouts, and train/calibrate Random Forest/XGBoost models per detector."*
11. *"Integrate the trained PS26145 models into the live detection layer: a model-loading wrapper with integrity-hash verification and rule-path fallback, and max-confidence combination when both a rule and its classifier fire."*
12. *"Add PS26145's MVP security controls: auth, CORS, input validation, file/PCAP validation, secrets management, model/dataset integrity hash columns, audit logging, and a passive-ingest no-egress network-namespace test plus a Docker lateral-reachability check."*
13. *"Run and fix the full PS26145 test suite (unit, ML validation, integration, system, security, six architectural-compliance tests) together for the first time, resolving any cross-suite regressions."*
14. *"Build and run a PS26145 performance-benchmark harness measuring real flows/sec, Mbps, feature/inference/end-to-end latency percentiles, queue depth, drop counts, CPU, and memory, and update all documentation to cite the measured numbers."*
15. *"Finalize the PS26145 Docker Compose hackathon deployment, pre-build all images, and verify two independent clean-machine startups with zero runtime internet dependency."*
16. *"Rehearse the PS26145 15-step SIH demo sequence three times on the actual demo hardware, recording fallback replay/video for every step and confirming the JA3 live-trigger and DGA-script steps are demo-ready or explicitly routed to their replay fallback."*

---

## D. Final SIH Demo Checklist

**Setup:** pre-built images loaded; `docker compose up` tested twice on demo hardware; no Wi-Fi dependency; laptop charged/on power.
**Data:** all seven labeled experiments present in the lab's storage; JA3 blocklist pinned and verified against the exact demo client.
**Detection flow:** all seven detectors confirmed working (six live-capable, C2 via accelerated replay by design, encrypted-malware rule-only with the disclosure line rehearsed).
**Dashboard:** all four MVP pages load; SSE live feed confirmed; Replay and Threat Analytics ready as high-value additions if built.
**Fallback plan:** a validated replay archive and a pre-recorded screen-capture video exist for every one of the 15 steps.
**Evidence:** Alert Detail evidence panels reviewed for at least one alert per threat; explanation text sanity-checked.
**Judge-facing validation:** the ten anticipated questions (from the skeptical-review task) rehearsed aloud; the real (Phase 14) throughput/latency numbers memorized, not the original unmeasured target.

---

## E. Requirement Traceability Matrix

| Official Requirement | Architecture Component | Implementation Module(s) | Test Evidence | Demo Evidence | MVP Status |
|---|---|---|---|---|---|
| DDoS detection | §8 hybrid architecture | `detection/rules/ddos.py`, `ml/train_ddos.py` | Phase 6/13 rule + ML tests | Demo step 4 | ✅ Full |
| C2 beaconing detection | §8 | `detection/rules/c2.py`, `ml/train_c2.py` | Phase 10/13 ML validation | Demo step 5 (replay) | ✅ Full |
| DGA detection | §8 | `detection/rules/dga.py`, `ml/train_dga.py` | Phase 10/13 | Demo step 6 | ✅ Full (pending Phase 3 script) |
| DNS tunnelling detection | §8 | `detection/rules/dns_tunnelling.py`, `ml/train_tunnelling.py` | Phase 10/13 | Demo step 6 | ✅ Full |
| Encrypted-session malware detection | §8 | `detection/rules/encrypted_malware.py` | Phase 6/13 rule tests only | Demo step 7 (disclosed limitation) | 🟡 Rule-only (documented) |
| Reconnaissance detection | §8 | `detection/rules/recon.py`, `ml/train_recon.py` | Phase 6/13 | Demo step 8 | ✅ Full |
| Data exfiltration detection | §8 | `detection/rules/exfiltration.py`, `ml/train_exfil.py` | Phase 10/13 | Demo step 9 | ✅ Full |
| Read-only ingest / no return path | §9, §13 | `ingest/`, capture container config | Phase 7/12 architectural-compliance + no-egress test | Demo step 2 (`ip addr` check) | ✅ Full |
| No active probing / no handshake | §13 | passive-ingest guardrails | Phase 7 architectural-compliance | Narrated throughout | ✅ Full |
| No inline mitigation | §9 | pipeline design (no write path back) | Phase 7 architectural-compliance | Narrated | ✅ Full |
| No TLS/QUIC decryption | §13 | `features/encrypted_malware.py` (metadata only) | Phase 7 architectural-compliance (no-key test) | Demo step 7 | ✅ Full |
| Streaming, not batch | §5, §9 | `streaming/pipeline.py` | Phase 7 incremental-processing test | Demo steps 2–3, 10 | ✅ Full |
| Bounded alert latency | §9, §15 | pipeline queue design | Phase 14 benchmark | Demo step 15 | 🟡 Target set, measured in Phase 14 |
| Demonstrated throughput | §15 | `benchmarks/` | Phase 14 benchmark report | Demo step 14 | 🟡 Target set, measured in Phase 14 |
| Standardized alert schema | §10 | `schemas/alert.py` | Phase 2 schema tests | Demo steps 11–12 | ✅ Full |
| Working prototype (source repo) | §17 | entire repo | Phase 13 full test pass | Full demo | ✅ Full |
| Documentation of models/features/training | this document + `docs/` archive | `docs/` | N/A | Available on request | ✅ Full |
| Dashboard, live or replayed, severity+confidence | §12 | `frontend/src/pages/*` | Phase 9 smoke tests | Demo steps 10–13 | ✅ Full |

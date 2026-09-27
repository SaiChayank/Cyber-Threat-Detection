# PS26145 — Implementation & Deployment Structure
**Scope:** How the already-approved architecture gets built and run, plus the repository layout it lives in. No implementation code is written here.

**Note:** this design adopts the final pre-blueprint audit's simplification finding (C1/H2) — a single-host Docker Compose environment replaces the originally-documented multi-VM lab topology as what's actually *built*, while the multi-VM design remains valid documentation of the production-representative architecture it approximates.

---

## 1. Local Development Environment

**Purpose:** fast, single-developer iteration on code — not a full attack-simulation environment.

- **Everything runs as local processes**, no containers required at this level: the FastAPI backend, the runtime pipeline (as an `asyncio` process), a local Redis instance (installed natively or run as a single throwaway container — the only exception to "no containers," since installing Redis natively varies too much by OS to be worth standardizing), and SQLite as the database (a file in the repo's local data directory, gitignored).
- **Traffic source for development is a small set of committed synthetic fixture pcap/flow files** (the same fixtures used by the integration golden-file tests from the verification strategy) — a developer working on, say, the DGA feature logic does not need the full lab running; they replay a fixture file directly through the pipeline.
- **Frontend runs via its own dev server** (Vite), pointed at the local backend, with hot-reload — entirely separate from the Python process.
- **Priorities served:** simple setup (a few `pip install`/`npm install` commands and one Redis instance), fully offline (fixture-based, no network dependency), minimal hardware (runs comfortably on a single laptop).

---

## 2. Minimal Hackathon Deployment

**Purpose:** the actual environment used for building toward and running the judged demo — a full, self-contained, single-host system, replacing the original multi-VM lab design per the audit's simplification finding.

- **Single host** (one laptop or one lab machine), everything orchestrated by Docker Compose (§3) rather than separate VMs — isolation is achieved via Docker's internal-only bridge networks rather than physically separate machines, which is sufficient to demonstrate every architectural property already designed (no egress, promiscuous capture, no IP on the capture interface) without the setup cost of provisioning multiple VMs.
- **No internet dependency required to run** — every component (Redis, SQLite/Postgres, the frontend build, the trained models) is local; the only place internet access is ever needed is during initial `docker compose build` (pulling base images and dependencies), not during actual operation or the demo itself — directly serving the offline/local-operation priority, which also matters practically for a venue with unreliable conference Wi-Fi.
- **Hardware expectation:** a single modern laptop (a handful of CPU cores, a few GB of RAM) — the whole point of moving off the multi-VM design is that this no longer requires a beefy host to run several full VMs simultaneously.

---

## 3. Docker Compose Deployment

**Services** (one Compose file, internal-only network by default):

| Service | Role |
|---|---|
| `benign-generator` | Runs iperf3/Ostinato/TRex-equivalent traffic generation (per the lab-architecture task's official tools) inside the internal network |
| `attack-simulator` | Runs hping3, Slowloris, dnscat2, iodine, DGA-query script, sandboxed C2 client, scanning tool, exfiltration script — one container, several invocable tools, matching the original lab's attack-simulator role |
| `victim` | The internal web/DNS/TCP target services attack and benign traffic are directed at |
| `c2-tunnel-endpoint` | The "attacker-side" C2 server and dnscat2/iodine server roles, kept entirely inside this same internal network |
| `capture` | Runs on the internal network with `NET_ADMIN`/promiscuous capability, performs the passive capture role — the container-based equivalent of the lab's dedicated monitoring host, still with no IP assigned to its capture-facing interface |
| `redis` | Redis Streams — the pipeline's ingest buffer and alert bus |
| `pipeline` | The `asyncio` runtime pipeline (Parser through Alert Output) |
| `backend` | The FastAPI application |
| `db` | SQLite as a mounted volume for the hackathon deployment (no separate DB container needed); noted here as a volume mount on `backend`, not a standalone service, consistent with SQLite's file-based nature |
| `frontend` | The built React app, served as static files (e.g., via a lightweight static file server) |

**Networks:** two Compose networks, mirroring the original lab design's two-segment topology conceptually — an `internal` network (no external egress) carrying all simulated traffic, and a `control` network carrying orchestration/logging/Redis/backend traffic — so the same "capture sees traffic, orchestration never touches the monitored segment" property from the original lab design is preserved even though everything now runs on one host.

**Reproducibility:** the entire environment stands up with one `docker compose up`, and tears down cleanly with one `docker compose down` — a judge or teammate can reproduce the exact demo environment without manual configuration steps, directly serving the reproducibility priority.

---

## 4. Optional Production Architecture

Kept brief, since this is explicitly optional and several of its pieces were already noted in earlier tasks:

- **Real hardware data diode or a dedicated SPAN/mirror port** replaces the Docker-internal capture container — the actual passive-observation boundary the whole system is designed around.
- **PostgreSQL** replaces SQLite (per the backend task's storage recommendation), with a dedicated least-privilege application role (per the security review).
- **A dedicated time-series store** for `system_metrics` at real production write-volume (flagged, not chosen, in both the backend and security tasks).
- **Redis Streams' documented future upgrade path to Kafka** (per the runtime-pipeline task) if sustained throughput needs exceed what a single Redis instance comfortably handles.
- **Multi-host separation** reintroducing something like the original lab's VM-per-role topology, but now for genuine production isolation reasons (real network segmentation, real hardware trust boundaries) rather than as a hackathon-build requirement.

---

## Repository Structure

```
ps26145/
├── ingest/
├── schemas/
├── streaming/
├── features/
├── detection/
├── ml/
├── alerts/
├── backend/
├── persistence/
├── frontend/
├── replay/
├── benchmarks/
├── tests/
├── deployment/
└── docs/
```

### `ingest/`
- **Responsibility:** Passive capture and format parsing — the Passive Ingest and Parser stages of the runtime pipeline. Turns raw bytes (from a live capture interface or a replayed archive file) into format-specific structured records (PCAP packet, NetFlow/IPFIX/sFlow record).
- **Important modules:** capture-source adapters (one per input format), the malformed-record/dead-letter handling logic.
- **Dependencies:** `schemas/` (for the record types it eventually hands off to); no dependency on anything downstream (detection, ML, backend) — this module's whole job ends at producing parsed, format-specific records.

### `schemas/`
- **Responsibility:** The canonical data model — `FlowRecord`, `DNSRecord`, `TLSQUICMetadata` (from the data-model task) and the final alert schema (from the alert-architecture task). The single source of truth for field names/types every other directory imports from.
- **Important modules:** the three canonical record definitions, the alert record definition, shared enums (`threat_class`, `severity`, `detector_type`).
- **Dependencies:** None internal — this is the most upstream directory in the codebase; every other directory depends on it, it depends on nothing else in the repo.

### `streaming/`
- **Responsibility:** The Normalizer and Streaming State stages — converting format-specific records into canonical schema objects, and hosting the keyed windowing/state primitives (Welford accumulators, EWMA, HyperLogLog, Count-Min Sketch, Bloom filters, per the feature-engineering task), plus the watermarking/allowed-lateness and window-expiry logic.
- **Important modules:** the normalizer (per input format to canonical schema), the state-store abstraction (sharded by key), the sketch-structure wrappers (using existing lightweight libraries per the final audit's complexity finding, rather than hand-rolled implementations).
- **Dependencies:** `schemas/` (for the canonical types it produces and stores), `ingest/` (consumes its output).

### `features/`
- **Responsibility:** Feature Extraction — computing the per-detector feature vectors defined in the feature-engineering task, reading from `streaming/`'s state.
- **Important modules:** one feature-computation module per threat (DDoS, C2, DGA, DNS tunnelling, encrypted-malware, reconnaissance, exfiltration), each producing the exact feature set specified for its detector.
- **Dependencies:** `streaming/` (reads keyed state), `schemas/` (input record types).

### `detection/`
- **Responsibility:** Detection, Confidence/Severity, and Evidence stages — the rule baseline logic, the ML-detector inference wrapper (loading a versioned model from `ml/`'s registry), the calibration application, severity calculation, evidence-object construction, explanation-template rendering, and alert deduplication logic.
- **Important modules:** one rule module per threat (from the rule-baseline task), one ML-detector wrapper per threat (loading a specific `model_version`), the confidence-combination logic for hybrid alerts, the severity formula, the per-threat explanation templates, the dedup/cooldown state.
- **Dependencies:** `features/` (its input), `ml/` (for trained model artifacts and calibration parameters), `schemas/` (evidence/alert shape).

### `ml/`
- **Responsibility:** Everything training-related — dataset assembly from lab experiment archives, the experiment-level/temporal/scenario-separated splitting logic, model training scripts per detector/model family, calibration fitting, and the model-versioning/registry bookkeeping (hashes, metadata) that `detection/` reads from.
- **Important modules:** the split-construction logic (shared, not duplicated per model), one training script per detector, the calibration-fitting module, the model-registry writer.
- **Dependencies:** `replay/` and `features/` — **critically, `ml/`'s training-data generation reuses the same `replay/` to `ingest/` to `streaming/` to `features/` code path used at live inference time**, rather than a separate offline batch tool. This is the structural implementation of the final audit's Correction 2 (option b): eliminating the train/serve feature-computation skew risk by construction, since there is now only one feature-computation implementation, not two.

### `alerts/`
- **Responsibility:** The Alert Output stage — assembling the final alert object from a detection result plus its evidence, and publishing it onto the Redis Streams alert bus for the backend to consume.
- **Important modules:** the alert-object builder, the Redis-publish client.
- **Dependencies:** `detection/` (its input), `schemas/` (the alert shape it produces).

### `backend/`
- **Responsibility:** The FastAPI application — REST endpoints, the SSE live-alert stream, the Redis Streams consumer (Ingestion Adapter), and the internal modules from the backend-design task (Alerts, Live Broadcast, Replay, Model Registry, Metrics, Feedback, Audit).
- **Important modules:** one router per capability area (alerts, replay, models, metrics, feedback, audit), the Ingestion Adapter's consumer task, the SSE broadcast manager.
- **Dependencies:** `persistence/` (all database access), `schemas/` (request/response models); consumes from the Redis stream `alerts/` publishes to (no direct Python import dependency on `alerts/`, only a runtime message-bus relationship — deliberately decoupled, per the backend design's "the backend never reaches into pipeline internals" principle).

### `persistence/`
- **Responsibility:** Database models and access — the six entities from the backend-design task (`alerts`, `replay_sessions`, `model_versions`, `system_metrics`, `analyst_feedback`, `audit_events`), their relationships, indexes, and the SQLite/PostgreSQL connection handling for the dev/hackathon/production environments respectively.
- **Important modules:** one ORM model per entity, the migration scripts, the query helpers `backend/`'s routers use.
- **Dependencies:** `schemas/` (aligning stored alert fields with the canonical alert schema); no dependency on `backend/` itself, kept as a clean data-access layer `backend/` calls into, not the reverse.

### `frontend/`
- **Responsibility:** The React/Vite SOC analyst dashboard — the MVP, high-value, and future pages from the SOC-UI task.
- **Important modules:** one page component per selected page (Overview, Live Detections, Alerts, Alert Detail, Replay, Threat Analytics), the shared API client (REST + SSE), the reusable severity-badge/confidence-indicator/threat-specific-evidence components.
- **Dependencies:** Only the backend's HTTP/SSE API surface — no direct dependency on any other repo directory, since the frontend is a fully separate deployable artifact from the Python codebase.

### `replay/`
- **Responsibility:** Reading archived experiment data (per the lab-architecture task's storage structure) and feeding it into `ingest/` at a chosen pace (real-time-paced or accelerated, per the runtime-pipeline task), plus replay-session lifecycle management.
- **Important modules:** the archive reader, the pacing controller, the session-state tracker (used by both live-demo replay and, per `ml/`'s dependency above, training-data generation).
- **Dependencies:** `ingest/` (feeds into it), `schemas/` (experiment/session metadata shape).

### `benchmarks/`
- **Responsibility:** The performance-measurement scripts from the verification-strategy task — throughput/Mbps load generation, latency percentile measurement at each pipeline stage boundary, queue-depth and drop-event sampling, CPU/memory profiling over sustained runs.
- **Important modules:** the load-generator driver (using `replay/`'s accelerated mode), the latency/queue-depth instrumentation hooks, the report generator that produces the committed performance numbers.
- **Dependencies:** `replay/` (to drive load), read-only observation hooks into `streaming/`/`detection/` (queue depths, timings) — deliberately non-invasive, added as instrumentation rather than modifying pipeline logic.

### `tests/`
- **Responsibility:** Everything from the verification-strategy task — unit tests (mirroring `ingest/`, `features/`, `detection/` structure), the ML validation/false-positive/leakage test suite, integration (golden-file, dedup, hybrid-combination) tests, system tests (backend/database/dashboard/replay), the security-control checklist, and the six architectural-compliance tests.
- **Important modules:** subdirectories mirroring the source tree (`tests/ingest/`, `tests/features/`, etc.), plus dedicated `tests/architectural_compliance/` and `tests/security/` directories for the cross-cutting suites that don't map to one source directory.
- **Dependencies:** everything — by nature, the test suite imports from every other directory it verifies.

### `deployment/`
- **Responsibility:** Everything from this document — Dockerfiles per service, the Compose file(s) for dev/hackathon/production variants, the lab traffic-generator/attack-simulator configuration (DGA domain lists, C2 emulator config, internal fake-DNS-zone data), and any setup/teardown scripts.
- **Important modules:** `deployment/docker-compose.hackathon.yml`, `deployment/docker-compose.dev.yml`, per-service `Dockerfile`s, the lab configuration files.
- **Dependencies:** references every service directory (`ingest/`, `backend/`, `frontend/`, etc.) for what to containerize, but contains no application logic itself — purely orchestration and configuration.

### `docs/`
- **Responsibility:** Every approved design document produced across this project's tasks (Source of Truth, threat/data/dataset analysis, lab architecture, data model, feature engineering, rule baseline, ML architecture/model selection, model-development methodology, readiness review, runtime pipeline, alert schema, backend design, SOC UI, security review, final audit, verification strategy, this document) — the project's full paper trail, kept alongside the code it describes.
- **Important modules:** one file per design task, plus a top-level `README.md`/quickstart pointing a new contributor or judge at the right starting document.
- **Dependencies:** None — pure documentation, no code dependency in either direction.

---

**No implementation code has been written in this document** — this defines the deployment environments and repository layout only, per the agreed task scope.

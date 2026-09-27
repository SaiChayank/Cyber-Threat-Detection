# PS26145 — Application Backend Design
**Scope:** The backend service that sits between the runtime detection pipeline and the (not-yet-designed) dashboard/frontend. No frontend or security/auth design happens here — those are later, explicit tasks.

**Guiding constraint carried forward:** avoid unnecessary microservices, consistent with this project's repeated preference for the simplest option that satisfies the requirement (rules-first architecture, asyncio-over-Kafka, template-over-LLM explanations, etc.).

---

## BACKEND

### Framework

**Recommended: FastAPI**, as a single Python service.

- **Native `asyncio` fit:** the runtime pipeline is already built on `asyncio` and Redis Streams; FastAPI is built on the same async foundation (ASGI), so the backend can consume from Redis Streams, serve HTTP requests, and push live updates to clients all within one event loop without bridging between incompatible concurrency models.
- **Built-in support for both API styles needed here:** standard REST endpoints, and (per the "Live Alert Transport" section below) streaming responses for live alerts — no additional framework needed to get both.
- **Pydantic integration:** the alert schema already designed (official/derived/optional fields) maps directly onto Pydantic models, giving free request/response validation and automatic API documentation — useful for a hackathon judging context where a clear, inspectable API surface is itself a point in the project's favor.
- **Rejected alternative — Flask/Django:** both are mature and viable, but neither has FastAPI's native async-streaming ergonomics, meaning either would need extra plumbing (e.g., Django Channels, or a separate async worker) to do what FastAPI does natively — unnecessary complexity given the "avoid unnecessary microservices/complexity" constraint.

### Internal Modules/Services

**One deployable service, internally modularized — not split into separate microservices.** The scale (a single-team hackathon prototype, one lab environment, moderate throughput target) does not justify the operational overhead of independently deployed services; module boundaries provide the same organizational clarity without the deployment/coordination cost.

| Module | Responsibility |
|---|---|
| **Ingestion Adapter** | Consumes from the runtime pipeline's Alert Output stream (Redis Streams consumer group, per the runtime-pipeline design); on each new alert, writes it to the database and hands it to the Live Broadcast module — the single integration point between this backend and the detection pipeline |
| **Alerts Module** | Serves the alert-related REST endpoints (current, detail, history, filters); owns query construction against the alerts table |
| **Live Broadcast Module** | Manages connected live-alert clients (see Live Alert Transport section) and fans out newly ingested alerts to them |
| **Replay Module** | Starts/stops/monitors replay sessions by instructing the runtime pipeline's replay-mode ingest (per the runtime-pipeline design) and tracks replay-session state in the database |
| **Model Registry Module** | Serves model-metadata endpoints, reading from the `model_versions` table populated by the model-development methodology's experiment-tracking/versioning process |
| **Metrics Module** | Serves throughput/latency/health endpoints, reading from `system_metrics` (populated by the runtime pipeline's own operational logging, per its backpressure/drop/failure design) |
| **Feedback Module** | Accepts analyst feedback on alerts (optional entity, per the original requirements task's classification — module exists so the schema/entity is usable, without implying this is a load-bearing MVP feature) |
| **Audit Module** | Records audit events (model activation, replay triggered, configuration changes) — read-mostly, write-light |

These are Python modules/routers within one FastAPI application (one process, one deployment unit), not separate services with their own network boundaries, databases, or deployment pipelines.

### Streaming Integration

- The backend runs a **background consumer task** (an `asyncio` task started at application startup) that reads from the Alert Output Redis Stream using a dedicated consumer group, exactly as the runtime-pipeline design anticipated Redis Streams' consumer-group model would support.
- Each consumed alert is: (1) persisted to the `alerts` table, (2) broadcast to any currently connected live clients via the Live Broadcast module, in that order — persistence happens first so a client connecting immediately after broadcast can still retrieve the alert via the history/detail endpoints without a race condition.
- **This is the only place the backend talks to the detection pipeline.** The backend does not reach into Streaming State, Feature Extraction, or Detection directly — it only ever consumes finished, structured alerts, keeping the backend decoupled from internal pipeline mechanics and safe to restart/redeploy independently of the pipeline itself.
- For **replay mode**, the Replay Module issues a start command to the pipeline (which stage exactly receives this command is a pipeline-side detail already covered by the runtime-pipeline design's replay-mode section) and the same Ingestion Adapter path handles resulting alerts — replay-mode alerts flow through the identical ingestion → persistence → broadcast path as live alerts, tagged with their `experiment_id`/`replay_session_id` for later filtering.

---

## DATABASE

### Required Entities

| Entity | Purpose |
|---|---|
| `alerts` | The alert records themselves — schema per the prior alert-architecture task (official + derived-required + optional fields) |
| `replay_sessions` | Tracks each replay run: which experiment(s) were replayed, pacing mode, start/end time, status |
| `model_versions` | One row per trained model version, per the model-development methodology's versioning scheme |
| `system_metrics` | Time-series operational data: throughput (flows/sec), latency percentiles, queue depths, drop/error counts — sourced from the runtime pipeline's own logging |
| `analyst_feedback` | True/false-positive judgments an analyst attaches to an alert (optional-feature entity, per the requirements task's classification) |
| `audit_events` | System-level events: which model version was activated when, which replay was triggered by whom, configuration changes |

### Relationships

```
model_versions (1) ──< (many) alerts            [alerts.model_version_id → model_versions.id, nullable
                                                   — null for pure rule-based alerts, per detector_type]

replay_sessions (1) ──< (many) alerts            [alerts.replay_session_id → replay_sessions.id, nullable
                                                   — null for live-mode alerts]

alerts (1) ──< (many) analyst_feedback           [analyst_feedback.alert_id → alerts.id]

model_versions (1) ──< (many) audit_events       [audit_events.model_version_id → model_versions.id, nullable]

replay_sessions (1) ──< (many) audit_events      [audit_events.replay_session_id → replay_sessions.id, nullable]
```

`system_metrics` is intentionally **not** foreign-keyed to anything — it's a standalone time-series table, queried by time range only, since operational metrics describe the pipeline's overall health rather than any single alert or model.

### Indexes

| Table | Index | Reason |
|---|---|---|
| `alerts` | `(timestamp)` | Every history/current-alerts query filters or sorts by time range — the single most common access pattern |
| `alerts` | `(threat_class, dst_ip, timestamp)` composite | Supports the dedup-key lookup pattern from the alert-architecture task (`threat_class`, `primary_entity_key`, time bucket) and per-threat filtered views |
| `alerts` | `(severity)` | Supports severity-filtered dashboard views (a common triage pattern — "show me criticals first") |
| `alerts` | `(model_version_id)` | Supports the auditability requirement — "show me every alert this model version produced" |
| `alerts` | `(replay_session_id)` | Supports retrieving all alerts from a specific replay/evaluation run |
| `system_metrics` | `(timestamp)` | Time-range queries are the only access pattern for this table |
| `analyst_feedback` | `(alert_id)` | Direct lookup of feedback for a given alert |
| `audit_events` | `(timestamp)` | Chronological audit trail review |

### Retention

- **`alerts`:** retained in full for the prototype's lifetime (lab-scale data volume makes this trivial). For a production posture, a documented retention window (e.g., a fixed number of days of full-fidelity records, per whatever compliance/storage-budget constraints apply) would be needed — not designed further here, since no such constraint has been specified for this project.
- **`system_metrics`:** the highest-volume, fastest-growing table by nature (continuous operational logging). At prototype scale, retaining raw records is fine. This is explicitly flagged as the first table that would need a **rollup/downsampling retention policy** (e.g., raw for a short recent window, hourly aggregates beyond that) in any real production deployment — noted as a forward-looking concern, not designed in detail here since it depends on the production storage choice below.
- **`audit_events`:** retained long-term by nature — an audit trail's value is in its completeness over time, so this table is not a retention-reduction candidate.
- **`model_versions` / `replay_sessions`:** low cardinality (one row per training run or replay session, not per event), retained indefinitely without meaningful storage cost.

---

## API

Minimum endpoint set, organized by the required capability:

| Capability | Endpoint | Notes |
|---|---|---|
| **Live/current alerts** | `GET /api/alerts/current` | Returns the most recent N alerts (default window, e.g., last hour) — the initial-load view before a live connection takes over |
| **Live/current alerts (streaming)** | `GET /api/alerts/stream` | Server-Sent Events endpoint — see justification below |
| **Alert details** | `GET /api/alerts/{alert_id}` | Full alert record including `supporting_evidence`, `explanation`, `raw_feature_snapshot` if present |
| **Historical alerts** | `GET /api/alerts/history` | Paginated, time-range-bounded query (`start`, `end` required or defaulted) |
| **Filters** | Query parameters on both `.../current` and `.../history`: `threat_class`, `severity`, `min_confidence`, `src_ip`, `dst_ip`, `detector_type`, `replay_session_id` | Implemented as filters on the same two endpoints rather than separate filter-specific endpoints, keeping the API surface minimal |
| **Replay — start** | `POST /api/replay/sessions` | Body: which `experiment_id`(s) to replay, pacing mode (real-time-paced or accelerated, per the runtime-pipeline design) |
| **Replay — status/list** | `GET /api/replay/sessions` / `GET /api/replay/sessions/{id}` | List all replay sessions / get one session's status and resulting alert count |
| **Analytics** | `GET /api/analytics/summary` | Aggregated counts by `threat_class` and `severity` over a given time range — the minimum needed to power dashboard summary charts |
| **Health** | `GET /api/health` | Liveness/readiness — is the backend up, is it connected to Redis Streams and the database |
| **Throughput/latency** | `GET /api/metrics/throughput` | Current and recent-historical throughput (flows/sec) and latency percentiles, read from `system_metrics` — this is the endpoint that would back the PS's mandated throughput demonstration |
| **Model metadata** | `GET /api/models` / `GET /api/models/{version}` | List all model versions with their training metrics, calibration info, and active/retired status; detail view for one version |
| **Analyst feedback** *(optional entity, minimal endpoint)* | `POST /api/alerts/{alert_id}/feedback` | Exists so the `analyst_feedback` entity is usable; not treated as an MVP-critical capability, consistent with its optional classification |

No endpoint set beyond this is proposed as "minimum" — anything more (e.g., a dedicated correlation endpoint, since correlation was already deferred past MVP) is out of scope here by the same reasoning already established in the alert-architecture task.

---

## Live Alert Transport: SSE, not WebSocket

**Recommended: Server-Sent Events (SSE).**

**Justification:**
- **The data flow is inherently one-directional** — the server pushes new alerts to the dashboard; the dashboard does not need to push arbitrary data back to the server over the same connection (filter changes, for instance, are naturally handled as a new HTTP request with query parameters, or a fresh SSE connection with new parameters — not a message sent over an already-open live channel). WebSocket's core advantage — full-duplex communication — solves a problem this use case doesn't have.
- **Simplicity, directly serving the "avoid unnecessary complexity" instruction:** SSE is plain HTTP — a long-lived response stream (`text/event-stream`) — with no separate protocol upgrade handshake, no separate library needed on most clients (the browser's native `EventSource` API handles it), and automatic reconnection built into that same browser API. WebSocket requires more client-side connection-management code for equivalent reliability.
- **Infrastructure friendliness:** SSE works over plain HTTP/1.1 and HTTP/2, meaning it passes through standard reverse proxies, load balancers, and corporate/lab-network middleboxes without the special-casing WebSocket connections sometimes need — a relevant concern for a system explicitly designed around a security-monitoring/enterprise-network context.
- **FastAPI supports SSE natively** via a streaming response, requiring no additional dependency beyond what the framework already provides — consistent with the "one framework, one service" backend design above.
- **When WebSocket would become the right choice (explicitly not now):** if a future feature requires the client to send frequent, low-latency messages back over the same channel — e.g., a live multi-analyst collaborative view where one analyst's action needs to be pushed to others in real time, or an interactive "acknowledge this alert" flow with immediate cross-client confirmation — that would justify WebSocket's duplex capability. No such requirement exists in the current scope (analyst feedback, per the API table above, is a simple REST POST, not a live duplex interaction).

---

## Storage Recommendations

### A. Prototype

- **Relational entities (`alerts`, `replay_sessions`, `model_versions`, `analyst_feedback`, `audit_events`):** **SQLite.** Zero setup (a single file, no separate server process to install or configure), which matters directly for hackathon time constraints, and entirely sufficient for the data volumes a lab-scale prototype will generate. FastAPI's async SQLAlchemy support works with SQLite for development without any code that would need to change in structure when moving to a real database later (only the connection string changes).
- **`system_metrics`:** also SQLite at this scale — the write volume from a single-lab-instance pipeline's periodic metrics logging does not approach the point where SQLite's single-writer limitation becomes a real constraint.
- **Live-alert bus:** the already-chosen Redis Streams instance from the runtime-pipeline design — no new component introduced for the backend; it reuses the same Redis process.

### B. Production

- **Relational entities:** **PostgreSQL.** Proper concurrent-write support, mature indexing (including the composite indexes specified above), and a natural upgrade path from SQLite (same SQL dialect family, same ORM layer, minimal application-code change).
- **`system_metrics`:** flagged in the retention section above as the table most likely to outgrow a general-purpose relational table at production scale and write-rate. A dedicated time-series-oriented storage approach (e.g., a time-series extension to the same PostgreSQL instance, or a purpose-built time-series store) would be the natural next step — not prescribed specifically here, since the right choice depends on production-scale metrics volume this design doesn't have visibility into yet.
- **Live-alert bus:** Redis Streams remains viable at moderate production scale; if the runtime-pipeline's own future-scale upgrade path (noted in that task as a possible move toward Kafka) is ever taken for the detection pipeline itself, the backend's Ingestion Adapter would need a corresponding consumer-client change — a contained, single-module change given the backend's modular design above, not a system-wide rework.

---

**No frontend/dashboard rendering and no security/authentication/authorization design have been performed in this document** — both are explicitly deferred to later, separate tasks.

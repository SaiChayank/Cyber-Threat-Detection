# PS26145 — Focused Security Review
**Scope:** Security controls relevant to the architecture already designed (lab, data model, feature pipeline, runtime pipeline, alert schema, backend, SOC UI). This is a review and classification exercise, not a redesign — no architectural component approved in prior tasks is changed here.

---

## Classification Summary

| # | Control | Classification | Rationale (brief) |
|---|---|---|---|
| 1 | Authentication | **MVP** | Even a demo prototype should not leave alert data (internal IPs, detection posture) reachable without credentials; cost is minimal |
| 2 | RBAC | **RECOMMENDED** | Only one functional role (SOC analyst) exists anywhere in the approved UI/API design — there's nothing yet to differentiate access between roles; worth adding if time allows, essential once multiple roles exist |
| 3 | API authorization (coarse read/write gating) | **MVP** | The same authentication gate must be verified to actually cover the state-changing endpoints (replay start, feedback submit), not just the read endpoints |
| 4 | CORS | **MVP** | The React frontend is a separate origin from the FastAPI backend by construction; an explicit allow-list is nearly free and closes an easy, common misconfiguration |
| 5 | Request limits (body size, timeout) | **MVP** | Cheap, framework-level protection against oversized/hanging requests to the write endpoints |
| 6 | Rate limiting | **RECOMMENDED** | Meaningful risk is low on a closed lab network with one legitimate client (the dashboard); worth adding, not blocking |
| 7 | Input validation | **MVP** | Nearly free given the backend's existing Pydantic-model design; every query/body parameter should be type/range-checked |
| 8 | File/PCAP validation | **MVP** | A genuine, PS-specific attack surface — the Replay module accepts references into lab-stored archives, which must be validated before reaching the Parser stage |
| 9 | Upload type/size restrictions | **NOT APPLICABLE** | No endpoint in the approved design accepts arbitrary user-uploaded files; replay works only against existing lab-indexed experiments. Becomes MVP the moment a direct pcap-upload feature is ever added — flagged, not silently dropped |
| 10 | WebSocket security | **NOT APPLICABLE** | The backend design deliberately chose SSE over WebSocket; there is no WebSocket endpoint in this architecture. Equivalent concerns for the SSE endpoint are covered under Authentication/CORS above |
| 11 | Secrets management | **MVP** | Credentials/connection strings must never be hardcoded; environment-variable-based config is essentially free to do correctly from the start |
| 12 | Database least privilege | **NOT APPLICABLE (prototype) / PRODUCTION (Postgres)** | SQLite (the recommended prototype store) has no user/privilege model, so this control has nothing to attach to yet; becomes directly applicable once PostgreSQL is adopted, per the backend design's own prototype→production storage split |
| 13 | Dependency security | **MVP** | Automatable, cheap (`pip-audit`/`npm audit`), and directly relevant given the number of third-party packages this stack already pulls in |
| 14 | Container security | **RECOMMENDED** | Containerization itself was never mandated by any prior task; if the team containerizes for reproducibility/judging, basic hygiene (non-root user, minimal base image) is cheap — full hardening is a production concern |
| 15 | Model integrity | **MVP** | Directly extends the model-versioning design already approved — a loaded model artifact should be verifiable against the hash recorded at training time |
| 16 | Dataset integrity | **MVP** | Directly extends the lab's already-designed experiment manifest — a hash per stored artifact protects the entire train/test methodology from silent corruption |
| 17 | Audit logging | **MVP** | The `audit_events` entity/table already exists in the approved backend design specifically for this; the remaining work is populating it for the events that matter |
| 18 | Tamper-evident alert logging | **RECOMMENDED** | Already named a FUTURE/production concern in the original requirements-analysis task ("tamper-proof/append-only logging with cryptographic chaining"); a lightweight version (a simple hash-chain field) is a reasonable stretch goal, full cryptographic anchoring is PRODUCTION |
| 19 | API abuse protection (beyond basic rate limiting) | **PRODUCTION** | A broader/more mature capability than item 6; not a meaningful risk on a closed lab network with one legitimate client |

---

## MVP Controls — Implementation Location and Test Method

### 1. Authentication
- **Implementation location:** A FastAPI dependency (e.g., `Depends(verify_credentials)`) applied to every router except `/api/health`. Simplest sufficient form for a prototype: a single shared bearer token read from an environment variable, checked on every request.
- **Test method:** Call a protected endpoint with no `Authorization` header and confirm `401`; call it with an incorrect token and confirm `401`/`403`; call it with the correct token and confirm the expected `200` response.

### 3. API Authorization (coarse read/write gating)
- **Implementation location:** The same authentication dependency from item 1, explicitly re-verified as applied to the two state-changing endpoints (`POST /api/replay/sessions`, `POST /api/alerts/{alert_id}/feedback`) — a deliberate check that write endpoints weren't accidentally left less protected than read endpoints during implementation.
- **Test method:** Attempt each write endpoint without credentials and confirm rejection; attempt with valid credentials and confirm the action succeeds and is recorded (cross-checked against item 17's audit log).

### 4. CORS
- **Implementation location:** FastAPI's `CORSMiddleware`, configured with an explicit `allow_origins` list containing only the known frontend origin(s) (e.g., the local dev server URL and, later, the deployed dashboard URL) — never a wildcard.
- **Test method:** From a browser or `curl` request bearing an `Origin` header not on the allow-list, confirm the response lacks the CORS headers needed for the browser to expose it to a disallowed origin's script; confirm a request from the allowed origin succeeds normally.

### 5. Request Limits
- **Implementation location:** ASGI-server-level (Uvicorn) request size/timeout configuration, plus explicit `Content-Length` checks in the write-endpoint handlers (replay-session creation, feedback submission).
- **Test method:** Submit a request body exceeding the configured size limit and confirm a `413 Payload Too Large` (or equivalent) response rather than the server attempting to process it; submit a deliberately slow/partial request and confirm the connection times out rather than hanging indefinitely.

### 7. Input Validation
- **Implementation location:** Pydantic models and typed query parameters on every FastAPI route (already implied by the backend design's use of Pydantic for the alert schema) — e.g., `min_confidence: float = Query(ge=0.0, le=1.0)`, `threat_class: ThreatClassEnum` rather than a free-text string.
- **Test method:** Send an out-of-range or wrong-type value for each constrained parameter (e.g., `min_confidence=5`, `severity=banana`) and confirm a `422 Unprocessable Entity` validation error, not a server-side exception or a silently-wrong query result.

### 8. File/PCAP Validation
- **Implementation location:** The Replay Module's session-start handler. Two checks, both before anything reaches the runtime pipeline's Parser stage: (a) the requested `experiment_id`(s) must exist in the lab's own `experiment_manifest.csv`/index — never accept an arbitrary filesystem path from the request body; (b) referenced archive files undergo a basic structural check (e.g., pcap magic-number/header validation) before being handed to Passive Ingest for replay.
- **Test method:** Attempt to start a replay session with (a) a nonexistent `experiment_id` — confirm a clear rejection, not a filesystem error; (b) a path-traversal-style string (e.g., `../../etc/passwd`) in place of an experiment ID — confirm it is rejected as an invalid identifier rather than resolved as a path at all; (c) a deliberately truncated/corrupted pcap file referenced by a valid-looking experiment ID — confirm it is routed to the existing dead-letter/quarantine path (already designed in the runtime pipeline) rather than crashing the Parser.

### 11. Secrets Management
- **Implementation location:** Environment-variable-based configuration (e.g., a Pydantic `BaseSettings` class) loaded once at FastAPI startup; a `.env.example` committed to the repository with placeholder values, the real `.env` excluded via `.gitignore`.
- **Test method:** Search the repository history and current tree for hardcoded credentials/tokens/connection strings before submission (a manual `grep` pass is sufficient at this scale); confirm the application fails to start with a clear error (rather than silently using an insecure default) if a required secret environment variable is missing.

### 13. Dependency Security
- **Implementation location:** Run `pip-audit` against the Python dependency set and `npm audit` against the frontend dependency set as a pre-submission step.
- **Test method:** Run both tools and confirm no high/critical-severity vulnerabilities remain unaddressed in direct dependencies; where a flagged vulnerability can't be resolved before submission, document it explicitly rather than silently ignoring the finding.

### 15. Model Integrity
- **Implementation location:** At model-load time in the Detection module (runtime pipeline), compute a hash of the loaded model artifact and compare it against the hash recorded in the `model_versions` table entry created at training time (per the model-development methodology's versioning scheme). On mismatch, refuse to load the model and fall back to the rule-only detection path for that threat (consistent with the hybrid architecture's rule-as-available-fallback design) — logging the mismatch as a security-relevant event (cross-referenced with item 17).
- **Test method:** Deliberately flip a byte in a saved model artifact file and confirm the system detects the hash mismatch on next load, refuses to use the corrupted model, and falls back to the rule path rather than silently running the tampered model.

### 16. Dataset Integrity
- **Implementation location:** Extend the lab-architecture task's experiment metadata manifest with a hash field per stored raw-pcap/flow artifact, computed once at capture-export time; the flow-extraction/training pipeline verifies this hash before using any archived file.
- **Test method:** Modify a stored pcap file's bytes after it has been hashed and confirm the training/evaluation pipeline detects the mismatch on its next read and refuses to silently include the altered file in a training/evaluation run.

### 17. Audit Logging
- **Implementation location:** The Audit Module already specified in the backend design. Hooks are added at: the authentication dependency (log failed auth attempts, with source IP and timestamp), the Replay Module (log every session start, by whom/when/which experiment), and the Model Registry Module (log model-version activation/deactivation changes).
- **Test method:** Trigger a failed login, a replay-session start, and a model-version change, and confirm each produces a corresponding row in `audit_events` with the correct event type, actor, and timestamp.

---

## Protecting the Passive Ingest Boundary from an Accidental Return-Path Dependency

This is the one control category that isn't a generic security-hardening item — it's a direct extension of the project's foundational constraint (read-only ingest, no active probing, no return path), and a security review's specific job here is to confirm that **no security or validation control added above accidentally reintroduces exactly the dependency the whole architecture was built to avoid.**

**Classification: MVP** — not because it requires new infrastructure, but because it is a discipline/verification check that must not be skipped, given how easy it is for a well-intentioned addition to violate it silently.

**Specific risks identified and how they're avoided:**
- **The capture/mirror NIC itself must never be given an IP address or any listening service**, as already established in the lab-architecture task — this review confirms no control proposed above (authentication, rate limiting, etc.) applies to or requires anything on that interface. All the controls above apply to the backend API and the Replay module's *stored-archive* access path, never to live capture itself.
- **File/PCAP validation (item 8) must remain purely structural and local** — checking a pcap's magic number, header fields, or basic size sanity must never be implemented by calling out to an external service (e.g., a cloud malware-scanning API), since that would introduce a live, active, outbound dependency into a system whose core premise is that its detection logic requires no such round-trip. This is an explicit implementation constraint on item 8, not a separate control.
- **DNS/domain-related validation must never resolve anything.** A tempting-but-wrong "helpful" addition would be to validate a DGA-flagged or tunnelling-flagged domain by actually resolving it or checking its reputation via a live lookup — this would be an active probe, directly violating the no-active-probing constraint established at the very start of this project. All DGA/tunnelling detection logic, and any future evidence-enrichment feature, must remain confined to what was passively observed plus static, offline-built reference tables (the n-gram model, any fingerprint list) — never a live query triggered by ingest or detection activity.
- **Verification test:** run the Passive Ingest capture path inside a network namespace (or equivalent sandbox) with all egress traffic blocked, and confirm capture and downstream processing continue to function identically. If ingest or any downstream stage silently depends on being able to reach out (DNS resolution, an external API call, a health-check ping), this test will surface it as a failure — a direct, falsifiable way to confirm no return-path dependency has crept in, rather than relying on code review alone.

---

**No architectural component approved in prior tasks has been redesigned here** — this document only classifies and specifies the security controls layered around the already-approved lab, pipeline, backend, and UI design.

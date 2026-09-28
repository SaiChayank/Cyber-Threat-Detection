# PS26145 — Implementation Plan
> Historical plan. The owner's supplied screenshots govern the current build; encrypted-session detection remains in scope. Current implementation and verification are described in `EXPECTED_SOLUTION.md` and the root README.
**Purpose:** a working document to execute against, day to day. Full rationale for every decision lives in the Master Blueprint (`PS26145_MASTER_BLUEPRINT.md`) — this file only tells you what to do, in what order, and how to know when to move on.

---

## How to Use This Plan

- Work top to bottom. Do not start a phase before the previous one's **Gate** passes.
- Phases 8–9 (backend/dashboard) and 10–11 (ML training/integration) can run **in parallel** if you have two people — everything else is strictly sequential.
- If time runs out anywhere after Phase 9, you still have a complete, honest, demoable six-threat rules-only system. That's not a fallback bolted on — it's why the phases are ordered this way.

---

## Effort Guide

Rough relative sizing (not calendar dates — fit to your actual timeline):

| Phase | Relative effort | Can parallelize? |
|---|---|---|
| 1. Bootstrap | XS | No |
| 2. Schemas | S | No |
| 3. Lab | M–L (has 3 open blockers — see below) | Partially |
| 4. Ingest/Parsing | M | No |
| 5. Features | L | No |
| 6. Rule Detectors | M | No |
| 7. Pipeline Assembly | L | No |
| 8. Backend | M | **Yes, parallel with 10–11** |
| 9. Dashboard | M | **Yes, parallel with 10–11** |
| 10. ML Training | L | **Yes, parallel with 8–9** |
| 11. ML Integration | S | Depends on 7 + 10 |
| 12. Security | M | No |
| 13. Full Test Run | M | No |
| 14. Benchmarking | S | No |
| 15. Deployment Packaging | S | No |
| 16. Demo Rehearsal | M | No |

**Milestone after Phase 9:** a fully working, honest, rules-only end-to-end demo exists. Treat this as your first real checkpoint — if you're behind schedule at this point, everything from Phase 10 onward is upside, not a requirement to hit.

---

## Before You Start: Three Things to Resolve First

These have been flagged as open across multiple prior reviews and block real work in Phase 3 — resolve them in your first working session, before writing any lab code:

1. **Pick a specific sandboxed C2 emulator tool.** Not yet chosen anywhere in the design. Any reasonable, controllable emulator works — the point is picking one, not finding the perfect one.
2. **Confirm DGArchive access/licensing**, or pick a substitute published DGA algorithm list if access is gated or delayed.
3. **Scope the DGA-domain-to-DNS-traffic script.** This is a small script (query generated domain strings against your internal fake resolver), not a new capability — just make sure someone owns writing it.

---

## Phase-by-Phase Action List

### Phase 1 — Bootstrap
- [ ] Create the 15 top-level directories (`ingest/ schemas/ streaming/ features/ detection/ ml/ alerts/ backend/ persistence/ frontend/ replay/ benchmarks/ tests/ deployment/ docs/`)
- [ ] `pyproject.toml` (Python 3.11+, FastAPI, Pydantic, `redis`, `pytest`)
- [ ] `frontend/` via `npm create vite@latest -- --template react-ts`
- [ ] Local Redis running
- [ ] `.env.example`, `.gitignore`
- [ ] One trivial FastAPI health endpoint + blank Vite page both start
- **Gate:** fresh clone → both dev servers start with zero manual fixes.

### Phase 2 — Schemas
- [ ] `FlowRecord`, `DNSRecord`, `TLSQUICMetadata` (Pydantic)
- [ ] Final alert schema (official + derived-required + optional fields, per the alert-architecture design)
- [ ] Validation round-trip unit tests
- **Gate:** all schema tests pass; treat this output as frozen going forward.

### Phase 3 — Lab
- [ ] Resolve the three pre-work items above
- [ ] Docker Compose: benign-generator, attack-simulator, victim, c2-tunnel-endpoint, capture (no IP, promiscuous), two internal-only networks
- [ ] DGA traffic-generation script
- [ ] Internal fake-DNS resolver zone
- [ ] Experiment manifest writer (ID, labels, timestamps)
- [ ] Capture at least one labeled experiment per threat (all seven)
- **Gate:** seven labeled experiments exist; capture interface confirmed to have no IP (`ip addr` check).

### Phase 4 — Ingest, Parsing, Normalizer
- [ ] PCAP parser (primary format)
- [ ] Malformed-record dead-letter path
- [ ] Normalizer → canonical schema
- [ ] Composite-key dedup at this stage
- **Gate:** every Phase-3 experiment parses into canonical records with zero unhandled exceptions.

### Phase 5 — Streaming State & Features
- [ ] Sketch primitives via `datasketch`/`probables` (not hand-rolled) + Welford/EWMA
- [ ] Watermarking, allowed-lateness, window-expiry, inactive-key eviction
- [ ] One feature module per threat (7 total)
- [ ] Completeness flag
- [ ] Static reference tables (DGA n-gram model, JA3 blocklist) — pre-cutoff-only build discipline
- **Gate:** all feature unit tests pass, including causality and memory-bound tests.

### Phase 6 — Rule Detectors + Alert Output
- [ ] One rule module per threat (7 total, including encrypted-malware blocklist + heuristic)
- [ ] Severity calculation
- [ ] Template-based explanation generation (+ boundary-value tests)
- [ ] Dedup/cooldown logic
- [ ] Alert builder + Redis publisher
- [ ] Curate the JA3 blocklist, including the specific fingerprint you'll use in the demo
- **Gate (milestone):** all seven rule detectors correctly fire/don't-fire on their scenarios; a real alert publishes to Redis.

### Phase 7 — Pipeline Assembly
- [ ] Wire Phases 4–6 into one `asyncio` pipeline, bounded queues at every boundary
- [ ] Backpressure/load-shedding at ingest
- [ ] Per-detector failure isolation
- [ ] Three distinct drop-type loggers
- [ ] Replay engine: real-time-paced + accelerated modes
- **Gate (milestone):** all six architectural-compliance tests pass (no probe, no return path, no inline blocking, no decryption, incremental processing, pre-completion alerting); live and replay produce equivalent alerts.

### Phase 8 — Backend *(parallel with 10–11)*
- [ ] Six persistence entities + relationships/indexes
- [ ] Ingestion Adapter (Redis consumer)
- [ ] Minimum API set (current/stream/detail/history/replay/analytics/health/metrics/models/feedback)
- [ ] SSE broadcast
- [ ] Auth (single token), CORS allow-list, input validation — now, not later
- **Gate:** API contract, auth, and SSE tests pass.

### Phase 9 — Dashboard MVP *(parallel with 10–11)*
- [ ] Overview, Live Detections, Alerts, Alert Detail pages
- [ ] Shared API client + severity/confidence components
- [ ] Loading/empty/error states per page
- **Gate:** all four pages pass smoke + state tests against a live backend.

**→ Milestone: full rules-only demo is possible from here regardless of what happens next.**

### Phase 10 — ML Training *(parallel with 8–9)*
- [ ] Assemble training data by replaying Phase-3 experiments through the **same** `streaming`/`features` modules used live — never a separate batch tool
- [ ] Experiment-level split; temporal + configuration holdouts
- [ ] Train Random Forest/XGBoost per classifier-primary detector (6 total)
- [ ] Fit calibration (Platt/isotonic)
- [ ] Model registry (hash, metadata, version)
- [ ] Run the ML validation suite against MVP team targets
- **Gate:** validation-gate report exists for all six classifiers, pass/fail explicitly recorded — no silent gaps.

### Phase 11 — ML Integration
- [ ] Model-loading wrapper with integrity-hash check + rule-path fallback
- [ ] Max-confidence hybrid combination logic
- [ ] Wire `model_version` into ML-derived alerts
- **Gate (milestone):** full hybrid system (6 ML-backed + 1 rule-only) running end-to-end, live and replay.

### Phase 12 — Security Hardening
- [ ] Model/dataset integrity hash columns (actually add them — this was flagged as still-prose-only)
- [ ] Specific `audit_events` types + hooks
- [ ] Dependency scan (`pip-audit`/`npm audit`)
- [ ] Passive-ingest no-egress test (network namespace, all egress blocked)
- [ ] Docker lateral-reachability check (capture container → other same-host services)
- [ ] Lightweight tamper-evident alert hash-chain (cheap, worth doing)
- **Gate:** 100% of the MVP security checklist passes, including the two new tests.

### Phase 13 — Full Test Suite Run
- [ ] Run unit + ML + integration + system + security + architectural-compliance together for the first time
- [ ] Fix any regressions surfaced by running them together
- [ ] Add a regression test guarding against future reintroduction of a second feature-computation implementation
- **Gate:** 100% pass, or every exception explicitly documented and justified.

### Phase 14 — Benchmarking
- [ ] Accelerated-replay load test → real sustained flows/sec
- [ ] p95 end-to-end latency, feature latency, inference latency
- [ ] One-hour memory-stability run
- [ ] CPU under sustained load
- [ ] **Update every document/demo line that currently cites the unmeasured target** to cite the real number
- **Gate:** a reproducible benchmark report exists and is what you'll actually say out loud at the demo.

### Phase 15 — Deployment Packaging
- [ ] Finalize `docker-compose.hackathon.yml`, pre-build images
- [ ] `README.md`/quickstart
- [ ] Confirm zero runtime internet dependency
- [ ] Clean-machine dry run (ideally a second laptop)
- **Gate:** two independent clean-environment startups succeed.

### Phase 16 — Demo Rehearsal
- [ ] Rehearse all 15 demo steps three times on actual demo hardware
- [ ] Record fallback replay + screen-capture video for every step
- [ ] Pin and verify the JA3-trigger client version
- [ ] Confirm DGA step is demo-ready, or explicitly route it to replay-only
- [ ] Rehearse answers to the anticipated judge questions out loud
- **Gate:** three rehearsals done; every step has a working fallback; team can answer the hard questions without hesitating.

---

## If You're Running Out of Time

Cut in this order (matches the project's own MVP-vs-differentiator classification, nothing improvised):
1. Skip the lightweight tamper-evident hash-chain first.
2. Skip Threat Analytics / Replay pages (Overview + Live Detections + Alerts + Alert Detail is still a complete MVP).
3. If ML training (Phase 10) is at risk, ship the rules-only system from Phase 9 as your submission — it is complete, honest, and demoable on its own.
4. Never skip Phase 12's passive-ingest no-egress test or the six architectural-compliance tests — these are the properties the entire PS is judged on.

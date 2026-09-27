# PS26145 — SOC Analyst Interface Design
**Scope:** The analyst-facing frontend only, built on the already-designed backend API and alert schema. No backend/security work happens here.

**Official minimum requirement, restated:** the dashboard must show live or replayed detections with severity and confidence. Every page selected below is evaluated first against how directly it serves that requirement, then against general analyst usefulness.

---

## Page Evaluation

| Candidate Page | Serves official minimum? | Analyst usefulness | Verdict |
|---|---|---|---|
| **Overview** | Indirectly — a summary view is not literally required, but is the natural first screen an analyst opens, and can surface the throughput/latency demonstration the PS separately mandates without needing a dedicated page for it | High — gives immediate situational awareness | **MVP** |
| **Live Detections** | **Directly** — this *is* "live detections with severity and confidence" | Highest — the core operational view for an active SOC | **MVP** |
| **Alerts (historical/search)** | **Directly** — this covers "replayed detections" in the sense of any past alert, live or replay-sourced, and satisfies the earlier-established requirement to filter by class/time window | Highest — an analyst investigating a past incident needs this | **MVP** |
| **Alert Detail** | **Directly** — this is where `supporting_evidence`, `confidence`, and `severity` are actually read in full | Highest — an alert list without drill-down is not actionable | **MVP** |
| **Replay** | Supports "replayed detections" specifically, and is how the PS's throughput demonstration and evaluation-against-labeled-data actually get exercised | High for demoing/validating the system, but not something a working analyst touches during live operations | **High-Value** |
| **Threat Analytics** | Not required by name, but the requirements-analysis task already flagged trend/heatmap-style views as a reasonable optional enhancement | Moderate-high — valuable for pattern recognition over time, but secondary to acting on individual alerts | **High-Value** |
| **System Performance** | Not analyst-facing at all — this is an operator/engineer concern, not a SOC triage concern | Low for a SOC analyst specifically (though real for whoever runs the pipeline) | **Future** (a minimal throughput/latency widget is instead folded into Overview for MVP, per below, so the official throughput-demonstration requirement is still met without a dedicated page) |

---

# MVP UI

## 1. Overview

**Purpose:** The first screen an analyst (or a judge) sees — situational awareness at a glance, plus the compact metrics needed to satisfy the throughput-demonstration requirement without a dedicated performance page.

**Main components:** Summary counter cards (alerts in the last hour, by severity), a compact recent-alerts strip (last 5–10, clickable through to Alert Detail), a small live throughput/latency readout.

**Useful visualizations:**
- **Alerts over time** — a short-horizon line/area chart (last few hours), colored by severity, giving an immediate "is something happening right now" read.
- **Threat distribution** — a simple bar or donut chart of alert counts by `threat_class` over the same short horizon.

**Filters:** None at this level — Overview is intentionally filter-free; an analyst who wants to filter moves to the Alerts page.

**Required data/API fields:** `GET /api/analytics/summary` (counts by class/severity), `GET /api/alerts/current` (recent-alerts strip), `GET /api/metrics/throughput` (compact metrics readout).

**Real-time update requirements:** Summary counters and the recent-alerts strip subscribe to `GET /api/alerts/stream` (SSE) to increment/update live; the throughput readout polls `GET /api/metrics/throughput` on a short interval (SSE is unnecessary here since metrics change more slowly than alerts).

**Loading state:** Skeleton cards/chart placeholders while the initial `analytics/summary` and `alerts/current` calls resolve.

**Empty state:** "No alerts in the selected period" messaging with the charts rendering as empty-but-labeled (not blank/broken-looking) — an empty Overview is itself informative (system is healthy) and should read as calm, not as an error.

**Error state:** If `analytics/summary` or the SSE connection fails, show a non-blocking banner ("Live updates unavailable — showing last known data") rather than replacing the whole page with an error, since stale data is still useful to an analyst.

---

## 2. Live Detections

**Purpose:** The core operational view — a continuously updating feed of new alerts as they're generated, satisfying the official "live detections with severity and confidence" requirement directly.

**Main components:** A live-updating table/feed (newest first), each row showing `timestamp`, `threat_class`, `severity` (color-coded badge), `confidence`, `src_ip`/`dst_ip`, and a one-line `explanation` snippet; clicking a row opens Alert Detail.

**Useful visualizations:**
- **Confidence levels** — a small inline indicator per row (e.g., a filled bar or colored dot scaled to `confidence`) rather than a separate chart, so confidence is scannable at a glance across many rows.
- A slim **alerts-over-time sparkline** at the top of the feed, showing the live rate of incoming alerts.

**Filters:** `threat_class`, `severity`, `min_confidence`, `detector_type` — applied client-side against the live stream and also passed to the initial `alerts/current` load, so a filtered view stays filtered as new alerts arrive.

**Required data/API fields:** `GET /api/alerts/current` (initial load), `GET /api/alerts/stream` (SSE, ongoing).

**Real-time update requirements:** This page's entire reason to exist is real-time — it must be subscribed to the SSE stream continuously while open; new matching alerts prepend to the feed with a brief highlight animation so an analyst notices what's new without the whole list visually jumping.

**Loading state:** A skeleton feed (a few placeholder rows) while the initial load resolves, with the SSE connection opening in parallel.

**Empty state:** "No detections yet" with a small reassurance that the live connection is active (e.g., a pulsing "listening" indicator) — distinguishing "nothing has happened" from "the feed isn't working."

**Error state:** If the SSE connection drops, show a visible (not just a quiet banner, since this page's core value depends on it) "Live feed disconnected — reconnecting…" indicator with automatic reconnection (native to `EventSource`, per the backend design's transport choice) and a manual "refresh now" fallback.

---

## 3. Alerts (Historical / Search)

**Purpose:** Investigation and audit — an analyst searching for a specific past incident, reviewing everything in a time window, or preparing a report, satisfying the "replayed detections" and filter-by-class/time-window requirements.

**Main components:** A filterable, paginated table (same row shape as Live Detections, for visual consistency), a date-range picker, an export/report affordance (lightweight — not a full reporting subsystem, which remains an optional enhancement per the original requirements classification).

**Useful visualizations:** A compact **alerts-over-time** chart above the table reflecting the currently applied filters/date range — turning the table itself into a drill-down from the chart rather than two disconnected views.

**Filters:** `threat_class`, `severity`, `min_confidence`, `src_ip`, `dst_ip`, `detector_type`, `replay_session_id`, `start`/`end` date range — the full filter set the backend API supports.

**Required data/API fields:** `GET /api/alerts/history` (paginated, filtered).

**Real-time update requirements:** None — this is a query-driven page by design; it does not need a live subscription, since "historical" implies a fixed, analyst-chosen window rather than an ever-growing live feed.

**Loading state:** Table skeleton rows plus a disabled filter panel while a query is in flight, so an analyst doesn't submit overlapping queries.

**Empty state:** "No alerts match these filters" with the currently applied filters summarized and a one-click "clear filters" action — this is a very common state (an analyst narrowing a search too far) and should never look like an error.

**Error state:** A clear inline error ("Could not load alerts — retry") with a retry button; since this page is query-driven rather than live, a simple retry is sufficient without needing reconnection logic.

---

## 4. Alert Detail

**Purpose:** Where an analyst actually makes a decision — the full evidence trail behind one specific alert, satisfying the requirement that confidence and severity be inspectable in full, not just summarized in a list.

**Main components:** Header (threat class, severity badge, confidence value, timestamps, detector type/model version), a structured evidence panel (rendering `supporting_evidence` per the threat-specific shapes already defined in the alert-architecture task), the generated `explanation` text prominently displayed, network context (`src_ip`/`dst_ip`/ports/protocol), and a feedback control (true/false-positive) wired to the feedback endpoint.

**Useful visualizations, threat-specific (rendered conditionally based on `threat_class`):**
- DDoS / Reconnaissance: **traffic rate** chart (the `dst_packet_rate`/`scan_attempt_rate` time series leading up to the alert) and, for reconnaissance specifically, a **scan fan-out** visualization (targeted ports/hosts).
- DGA / DNS Tunnelling: **DNS anomaly statistics** — entropy/NXDOMAIN-ratio or record-type-distribution bar chart drawn from the evidence payload.
- C2 Beaconing: an inter-arrival-timing visualization (the periodicity pattern that drove detection).
- Encrypted-Session Malware: a simple packet-size sequence sparkline alongside the fingerprint identity.
- Data Exfiltration: a byte-ratio/volume bar comparing outbound vs. inbound.

**Filters:** None — this is a single-record view, not a search surface.

**Required data/API fields:** `GET /api/alerts/{alert_id}` (full record), `GET /api/models/{version}` (to show model context if `model_version` is present), `POST /api/alerts/{alert_id}/feedback` (for the feedback control).

**Real-time update requirements:** None required — an alert's core fields don't change after creation, except in the dedup-update case (§ from the alert-architecture task) where an ongoing condition's alert gets updated in place; if that applies, a light polling refresh (not SSE) on this one record is sufficient.

**Loading state:** A skeleton layout matching the eventual structure (header bar, evidence panel placeholder) rather than a generic spinner, since this page has a known, fixed shape.

**Empty state:** Not applicable in the usual sense — this page always has exactly one alert as its subject; the relevant "empty" case is a missing/invalid `alert_id`, handled as an error state instead.

**Error state:** "Alert not found" (invalid or deleted ID) or "Could not load alert details — retry," each distinct from each other, since one is a navigation mistake and the other is a transient failure.

---

# High-Value UI

## 5. Replay

**Purpose:** Lets an analyst (or, more likely in a hackathon demo context, the team demonstrating the system) run historical/lab-recorded traffic through the live detection pipeline — directly exercising the "replayed detections" requirement and the throughput-benchmarking capability designed into the runtime pipeline.

**Main components:** A session launcher (select experiment(s), choose pacing mode — real-time-paced or accelerated, per the runtime-pipeline design), a running-session status panel, and a results view once a session completes.

**Useful visualizations:** A live **alerts-over-time** chart scoped to the active replay session (effectively a filtered version of the Live Detections feed), and, once complete, a summary **threat distribution** for that specific replay run — useful for showing "here's what the system caught in this labeled scenario."

**Filters:** Scoped by `replay_session_id` rather than free filtering — this page is about one session at a time.

**Required data/API fields:** `POST /api/replay/sessions` (start), `GET /api/replay/sessions/{id}` (status), `GET /api/alerts/current` or `/stream` filtered by `replay_session_id`.

**Real-time update requirements:** SSE subscription while a session is actively running (same mechanism as Live Detections, filtered), switching to a static summary once the session's status becomes "complete."

**Loading state:** A distinct "session starting…" state between clicking "start" and the pipeline confirming ingest has begun, separate from the general page-load skeleton.

**Empty state:** "No replay sessions yet" with the launcher prominent — this is the expected first-visit state, not a failure.

**Error state:** If a replay session fails to start (e.g., an invalid experiment ID) or fails mid-run (pipeline error), show the specific failure reason from the session status rather than a generic error, since debugging *why* a replay failed is itself valuable during development/demo prep.

## 6. Threat Analytics

**Purpose:** Pattern-level insight across many alerts over a longer horizon than Overview's short-window snapshot — supports an analyst or team lead looking for trends rather than acting on one alert.

**Main components:** A longer-range, filterable analytics dashboard — date-range selector plus a grid of charts.

**Useful visualizations:**
- **Alerts over time** — a longer-horizon version of Overview's chart (days/weeks rather than hours), stacked or colored by `threat_class`.
- **Threat distribution** — proportion of alerts by class over the selected range.
- **Confidence levels** — a histogram of confidence values per threat class, useful for spotting whether a given detector is systematically under- or over-confident (a natural companion to the calibration work already done).
- **Scan fan-out** — an aggregate view of reconnaissance activity (e.g., top sources by fan-out count over the range), not just the single-alert view Alert Detail already provides.
- **DNS anomaly statistics** — aggregate entropy/NXDOMAIN-ratio trends across all DGA/tunnelling alerts in range, useful for spotting a sustained campaign rather than one query burst.

**Filters:** Date range, `threat_class` (to isolate one threat's analytics), `detector_type` (rule vs. ML vs. hybrid — useful for informally sanity-checking the earlier "does ML add value" question against real alert volume, not just the offline evaluation).

**Required data/API fields:** `GET /api/analytics/summary` extended with the additional groupings above (by confidence bucket, by source for fan-out) — this may require the summary endpoint to accept additional query parameters beyond what was minimally specified in the backend design, a small, additive extension rather than a new endpoint.

**Real-time update requirements:** None — this is inherently a look-back, aggregate view; a manual refresh or periodic (e.g., every few minutes) re-fetch is sufficient, SSE is unnecessary overhead here.

**Loading state:** Chart-grid skeleton (placeholder chart frames) while the analytics query resolves.

**Empty state:** "No alert data in this range" per chart, individually, since a range might have data for one threat class but not another — better to show which specific charts are empty than to blank the whole page.

**Error state:** A retry affordance scoped to the whole analytics query, since these charts are typically fetched together from one endpoint call.

---

# Future SOC UI

## 7. System Performance (deferred)

**Purpose:** Operational health monitoring for whoever runs the pipeline (not a SOC analyst's day-to-day concern) — full historical throughput/latency, queue depths, drop counts, and per-detector health, extending the compact Overview widget into a dedicated diagnostic page.

**Why deferred rather than MVP:** the official throughput-demonstration requirement is already satisfiable via Overview's compact metrics widget; a full dedicated performance page adds real value for operating the system in production but is not what a SOC analyst needs to triage threats, and building it well (historical trend charts, per-detector breakdowns, drop/error visualizations) is exactly the kind of scope that should wait until the MVP and high-value pages are solid.

**Anticipated shape, for later design:** performance/latency time-series charts, per-detector error-rate/health indicators (surfacing the detector-failure-isolation design from the runtime pipeline), queue-depth/backpressure visualizations, and drop-event breakdowns (capture-level vs. overflow vs. late-arrival, per the runtime pipeline's distinct drop-tracking design) — not specified further here since this page is explicitly out of current scope.

---

## Recommended Frontend Stack

**React (with TypeScript) + Vite, TailwindCSS, Recharts, and native `EventSource` for SSE.**

**Justification:**
- **React** — component-based architecture maps naturally onto this design's page/widget structure (the confidence-indicator, severity-badge, and threat-specific evidence renderers in Alert Detail are exactly the kind of small, reusable components React is built for); by far the largest ecosystem for a hackathon team to move quickly in.
- **Vite over Next.js/SSR:** this is an internal analyst dashboard, not a public, SEO-sensitive site — there's no need for server-side rendering, and Vite's dev server and build are simpler and faster to iterate with, consistent with this project's repeated preference for the simplest sufficient option.
- **TailwindCSS** — fast to build consistent severity-color-coding, badges, and layout without hand-rolling a design system, appropriate for hackathon time constraints.
- **Recharts** — covers every visualization type specified above (line/area for alerts-over-time and traffic rate, bar for threat distribution and DNS anomaly stats, histogram-style bar for confidence levels) with a lightweight API, avoiding the heavier setup cost of a more powerful but complex charting library this project's chart needs don't actually require.
- **Native browser `EventSource`** for SSE — directly matches the backend's SSE transport choice with zero additional client library; this pairing (FastAPI's native SSE support + the browser's native `EventSource`) is what makes the SSE-over-WebSocket decision in the backend design pay off on the frontend side too, avoiding a WebSocket client library that would otherwise be needed for no functional benefit.
- **A lightweight data-fetching layer** (e.g., a small hook-based fetch wrapper, or a minimal library like TanStack Query if request caching/deduplication across pages becomes worth the dependency) handles the REST calls (`/alerts/history`, `/analytics/summary`, etc.), kept separate from the SSE-driven live state so the two data-update mechanisms (poll/fetch vs. push) don't get tangled in one abstraction.

---

**No backend or security/authentication design has been altered or extended here** — this document specifies only what the frontend needs from the already-designed API, per the agreed task scope.

# Univect website and analyst interface

The website implements the supplied PS26145 requirements on top of the existing
passive detection pipeline. This redesign preserves the Python models, metadata
extractor, read-only capture parser, event-time replay and SQLite alert history.

## Stack and layout

- Next.js 16 App Router, React 19 and strict TypeScript.
- Tailwind CSS 4 for the shared dark palette, responsive layouts and UI styling.
- Radix UI for accessible tabs, dialogs and tooltips; shared Button/Panel/Skeleton components.
- Motion for staggered entrances, scroll reveals, hover, numeric, tab and notification
  transitions; reduced-motion support.
- Lucide React icons and Recharts for actual sampled telemetry.
- React Hook Form + Zod for replay inputs and runtime API contract validation.
- Three.js for original robots, curved wire conveyors, metallic signal tokens,
  red portal shader, environment lighting and bloom. No reference video/model is embedded.
- Locally hosted Space Grotesk and DM Sans via `next/font/local`; license notices
  are under `frontend/public/assets/licenses/`. Builds do not request Google Fonts.
- Existing FastAPI, Pydantic and SQLite backend.

```text
frontend/src/
  app/                 Routes, metadata, layout, loading/error/404 boundaries
  components/          Brand, providers, AnimatedNumber, Reveal, 3D wrapper, reusable UI
  features/landing/    Hero, platform, threat tabs, architecture
  features/monitor/    Replay, metrics, chart, observation context, coverage, table, evidence
  hooks/               Health polling and monitor fetch/SSE lifecycle
  services/            Same-origin typed API access
  schemas/             Zod API contracts and replay validation
  constants/           Required categories and detector labels
  lib/                 Cached formatting, shared motion easing, Tailwind class utilities
  assets/fonts/        Licensed local WOFF2 files
  scene.ts             Procedural Three.js geometry/materials/animation
scripts/               Local service runner and Python setup
backend/               Existing passive pipeline API
```

## Install and run

Install Node.js 22.14+ and Python 3.11+ on PATH, then run from the repository root:

```sh
npm install
npm run dev
```

Open `http://localhost:3000/` and `http://localhost:3000/monitor`. The runner creates
a local Python virtual environment and installs `requirements.txt` if needed.
It starts one FastAPI worker and Next.js, both bound to loopback. A compatible
running API is reused and is not shut down when this launcher exits. Ctrl+C stops
the services created by this launcher, including Windows child processes.
The first Python setup needs network access for packages; subsequent runs use the
installed environment. Python remains required because the detector is a Python service.
If another application occupies port 3000, the launcher selects the next available
port through 3010 and prints the actual URL. An explicit `WEB_PORT` is never silently
changed; choose a free port if that setting conflicts with another service.

```sh
npm run build
npm start
npm run typecheck
npm run format
```

`npm run build` builds the website without starting the API. `npm start` runs the
production build and starts/reuses the API. A separate manual API can be launched
with `.venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`
on Windows, or `.venv/bin/python` on macOS/Linux. FastAPI's root redirects to the website.

## Environment

No secrets, paid services or API keys are required. Copy the root `.env.example`
to `.env` if customizing these defaults:

| Variable | Default | Purpose |
| --- | --- | --- |
| `API_HOST` | `127.0.0.1` | Python service bind address |
| `API_PORT` | `8000` | Python service port |
| `API_PROXY_URL` | `http://127.0.0.1:8000` | Server-only proxy destination |
| `WEB_PORT` | `3000` | Website port |
| `ALERT_DB` | `data/alerts.sqlite3` | Persistent alert database, relative to repo root |
| `PYTHON_EXECUTABLE` | local `.venv` interpreter | Optional explicit Python environment |

When `API_PORT` changes, update `API_PROXY_URL` too. The root commands load `.env`.
Next.js rewrites are generated at build time: rebuild after changing the proxy URL.
Restart an already-running API to apply Python environment/database changes. Commands
run directly within `frontend/` require the API to be started separately and use
the default proxy unless `API_PROXY_URL` is set in that shell.

## Implemented behavior

The landing page combines the stacked metallic character language of
[AiAf Agents](https://dribbble.com/shots/25941150-AiAf-Agents-3D-Landing-page-animation-ai-agents)
with the portal/conveyor concept of
[Portals](https://dribbble.com/shots/26011595-Portals-landing-page-web-design-3D-animation).
It is an original adaptation for Univect. The 3D illustration is labelled and
does not simulate real attack counts or geographic locations. Scenes load near the
viewport, pause offscreen or in background tabs, respect reduced motion, cap device
pixel ratio, and dispose GPU resources on navigation. A text/icon fallback handles
unavailable or lost WebGL contexts; the hero also has a pause/play control.

Both routes share `SiteNav`, `SiteFooter`, the U/vector `BrandMark`, glass panels,
typography and black/red/white tokens. The Monitor sidebar has been replaced by
top navigation retaining all four section links, API reference, platform return
and passive-sensor constraints. Mobile navigation overlays the content rather
than shifting anchor positions, closes on selection, outside click or Escape,
and highlights the visible section. See `UNIVECT_DESIGN_SYSTEM.md` for the palette,
motion and accessibility conventions.

The landing hero reveals its three heading lines in a short stagger, followed by
the calls to action. Shared buttons use a restrained hover/focus sheen, while a
thin navbar progress line tracks page scrolling. These effects reuse the existing
Motion library and the shared `easeOut` curve rather than adding dependencies.

The Monitor starts with a compact observation header and replay controls, including
visible scenario/speed labels and the actual replay-state pill. Four metric cards
share a row at `lg`; below them a wide chart sits beside `ObservationContext`, which
shows the collection boundary and actual active-source, late-event and state-eviction
counters. The full-width alert investigation table precedes coverage and dataset
readiness. Coverage and the saved benchmark form adjacent panels at `xl`, and these
layouts stack at smaller viewport sizes.

The monitor fetches current telemetry, dataset readiness and the latest 200 alerts.
SSE supplies new alerts and reconnects using sequence IDs. Telemetry polling is
bounded to 24 recent chart samples. Replay controls select synthetic scenarios or
downloaded public-source presets, adjust speed, start/stop replay, or upload classic
Ethernet PCAP files up to 16 MiB. Input and server errors appear with recovery feedback.
The backend continues to process incrementally rather than awaiting a final report.

Search covers addresses, IDs and evidence. Class and severity filters work together.
The table pages ten records at a time; JSON export includes every loaded matching
record, across all pages. The evidence dialog displays actual numeric metrics,
score basis, severity, engine and connection/flow identifiers, with JSON copying,
Escape closing, focus trapping and restored keyboard focus.

Counters distinguish the current replay from persistent recorded history. Observed
event timestamps and chart labels use UTC. `/api/benchmark` reads the saved benchmark
with its workload and scope; that panel does not claim end-to-end capacity.
`/docs` and `/openapi.json` proxy the real API documentation.

`AnimatedNumber` initializes with the actual loaded value and animates subsequent
changes. Screen readers receive the current API value immediately, while the
interpolated visual text is hidden from accessibility APIs. Number formatting uses
a cached `Intl.NumberFormat` instance. Coverage bars express each module's share of
recorded alerts, with no implication of detection accuracy; `DatasetReadiness`
provides an animated, labelled disclosure of the existing preset information.
Chart updates, card entrances, replay-state changes and table page/class/severity
changes use restrained transitions. A connection pulse appears only for an
established stream, and the collection diagram's metadata flow moves only during
a running replay. Motion configuration, component guards, CSS media queries and
chart/3D settings honor `prefers-reduced-motion`.

Next.js compression is disabled for the local app because gzip buffered SSE alerts
during browser verification. The backend adds `no-transform` and `X-Accel-Buffering: no`.
When deploying behind a proxy, exclude `/api/stream` from compression and buffering
and allow long-lived connections. Ordinary assets may be compressed by that proxy.

## Verification and limits

The Monitor layout and motion refinement was rechecked on 29 September 2026.
The production build and TypeScript check passed, along with all 34 Python tests.
Browser checks covered actual live counters/chart updates, replay-dependent flow
motion, start/stop and a complete 256-event replay with alerts from all seven
modules in a temporary database. Search, class filtering, pagination, export,
evidence copying, dataset expansion, mobile-menu Escape/focus and 320/390/768px
Monitor layouts passed. The original database was restored with all 130 alerts,
and production landing/Monitor console error logs were empty. Reduced-motion
guards were reviewed in source; OS preference switching was not automated.

The Univect redesign was verified using a separate SQLite database rather than adding
test alerts to the existing analyst history. Browser checks covered landing/monitor
routing, streaming while replay was running, start/stop, all threat modules, class
filtering, evidence dialogs, JSON copying, Escape/focus return and downloaded filtered
JSON contents (nine DGA records with required evidence fields). Phone (320/390), tablet
(768) and desktop layouts were inspected with actual browser viewport overrides.
Mobile menus and stable section anchoring were checked. API outage feedback, disabled
replay controls and reconnection were checked. Invalid and valid PCAP requests were
verified through the Next.js proxy, including three parsed packets. Browser file-picker
automation timed out, so file selection itself was not reverified in this redesign.
The earlier migration also verified public CIC DNS replay, search and pagination.
Production build, strict type checking and the 34-test Python regression suite pass.

This is a local research prototype. It does not add authentication or multi-user
authorization. Detection scores remain synthetic-trained posteriors or heuristic
strengths, not calibrated compromise probabilities. Public validation reports major
DGA false positives, no DNS tunnelling detections in tested public PCAPs and weak
external DDoS generalization. Raw QUIC handshake fingerprints, TCP reassembly and
PCAPNG are still unsupported. See `MODEL_AND_VALIDATION.md`, `STREAMING_VALIDATION.md`
and `DATASETS.md` for the detailed evidence. A nonfatal GPU shader precision warning
was observed on this device; the scenes render correctly and emit no runtime errors.

Recommended next work: improve public-data calibration and false-positive rates,
broaden replay/capture adapters, and add authenticated roles, audit trails and secure
deployment controls before exposing the analyst service outside the local machine.

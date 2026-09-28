# Sentinel website and analyst interface

The website implements the supplied PS26145 requirements on top of the existing
passive detection pipeline. This redesign preserves the Python models, metadata
extractor, read-only capture parser, event-time replay and SQLite alert history.

## Stack and layout

- Next.js 16 App Router, React 19 and strict TypeScript.
- Tailwind CSS 4 for the shared dark palette, responsive layouts and UI styling.
- Radix UI for accessible tabs, dialogs and tooltips; shared Button/Panel/Skeleton components.
- Motion for entry, hover, tab and notification transitions; reduced-motion support.
- Lucide React icons and Recharts for actual sampled telemetry.
- React Hook Form + Zod for replay inputs and runtime API contract validation.
- Three.js for original robots, curved wire conveyors, metallic signal tokens,
  purple portal shader, environment lighting and bloom. No reference video/model is embedded.
- Locally hosted Space Grotesk and DM Sans via `next/font/local`; license notices
  are under `frontend/public/assets/licenses/`. Builds do not request Google Fonts.
- Existing FastAPI, Pydantic and SQLite backend.

```text
frontend/src/
  app/                 Routes, metadata, layout, loading/error/404 boundaries
  components/          Brand, providers, 3D lifecycle wrapper, reusable UI
  features/landing/    Navigation, hero, platform, threat tabs, architecture
  features/monitor/    Metrics, chart, replay, dataset coverage, table, evidence
  hooks/               Health polling and monitor fetch/SSE lifecycle
  services/            Same-origin typed API access
  schemas/             Zod API contracts and replay validation
  constants/           Required categories and detector labels
  lib/                 Formatting and Tailwind class utilities
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
with the purple portal/conveyor concept of
[Portals](https://dribbble.com/shots/26011595-Portals-landing-page-web-design-3D-animation).
It is an original adaptation for Sentinel. The 3D illustration is labelled and
does not simulate real attack counts or geographic locations. Scenes load near the
viewport, pause offscreen or in background tabs, respect reduced motion, cap device
pixel ratio, and dispose GPU resources on navigation. A text/icon fallback handles
unavailable or lost WebGL contexts; the hero also has a pause/play control.

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

Next.js compression is disabled for the local app because gzip buffered SSE alerts
during browser verification. The backend adds `no-transform` and `X-Accel-Buffering: no`.
When deploying behind a proxy, exclude `/api/stream` from compression and buffering
and allow long-lived connections. Ordinary assets may be compressed by that proxy.

## Verification and limits

The migration was verified using a separate SQLite database rather than adding test
alerts to the existing analyst history. Browser checks covered landing/monitor routing,
live streaming, replay start/stop, all threat modules, public CIC DNS replay (2,000
events), invalid and valid PCAP uploads (three parsed packets), search empty states,
class filtering, pagination, evidence dialogs, Escape/focus return and downloaded
filtered JSON contents. Phone (320/390) and tablet (768) layouts were inspected using
real iframe CSS viewports. API outage feedback and disabled replay controls were checked.
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

# Monitor investigation refinement

13 October 2026. Reuses the existing Univect design, Next.js/React, Tailwind,
Motion, Radix, Recharts and APIs. No dependencies, authentication layer, routes,
detectors, model artifacts, datasets or database schema were added or changed.

Inspected the completion plan, UI and reliability reports, frontend agent rules,
installed Next.js guides, Monitor/landing components, schemas, API/SSE hook and
existing browser integration script. The owner's current request authorizes
incremental frontend improvements alongside sequential project work.

## Changes and root cause

- **Hold/resume the investigation queue.** Hold freezes up to 200 loaded records,
  preserving rows while inspecting evidence. Ingest, SSE, metrics and SQLite
  continue; a notice counts newer **loaded** records. Resume shows the latest 200.
  It is not an unlimited queue, a replay stop or a loss of persisted history.
- **Detection-engine filtering.** Choices come from actual loaded alert records.
  Search, threat, severity and engine predicates combine; a visible clear action
  resets all filters. Export contains every matching displayed record across
  table pages, using the held snapshot when held.
- **Restrained motion.** Alert rows fade in briefly; queue notices expand/collapse
  smoothly. Existing panel, metric, chart, nav and landing motion are retained.
- **Reduced-motion bug fixed.** The installed Motion hook snapshots the browser
  preference at mount. The first integration run caught an active transition after
  changing preference while the page was open. One shared `useSyncExternalStore`
  hook now subscribes to media changes with listener cleanup; existing consumers
  and MotionConfig use it. Both routes stay usable with reduction enabled.

## Files changed

New `frontend/src/hooks/use-reduced-motion.ts` and
`frontend/src/features/monitor/alert-filters.tsx`; existing `alert-feed.tsx`,
`monitor.tsx`, `traffic-chart.tsx`, `metrics.tsx`, `coverage.tsx`,
`dataset-readiness.tsx`, `replay-controls.tsx`, `components/providers.tsx`,
`animated-number.tsx`, `reveal.tsx`, `site-nav.tsx`, landing `hero.tsx` and
`platform.tsx`. Most consumers change only their reduced-motion import.
The browser script gains regression coverage. Documentation: this report,
`FRONTEND.md`, `COMPLETION_PLAN.md` and the dated verification directory.
Pre-existing pending code changes remain outside this task's delta.

## Verification

Acceptance was [recorded before changes](verification/monitor-refinement-20261013/PROTOCOL.md).
Production browser runs use loopback ports **3013/8013** and newly generated
disposable SQLite databases, never the analyst-history database.

- TypeScript and production builds pass; final standard-port build is recorded
  separately from the isolated proxy build.
- Full backend suite: **333 passed**, one existing Starlette/httpx deprecation
  warning, **128.27 seconds**. No backend code changed in this task.
- First browser run: **22/23 passed**, with the reduced-motion failure preserved
  under `browser-before-fix`. After the correction and overflow regression:
  **24/24 passed** under `browser-after-fix`. Final coverage also exercises fresh
  reduced-motion load and re-enabling animation: **25/25 passed**; see
  `browser-final/results.json`.
- Existing navigation, start/stop/completion, PCAP input/errors, filters/search,
  alert dialog/copy/focus, export, metrics, unavailable/retry and SSE resume checks
  are retained. New coverage verifies frozen rows against real persisted/SSE
  alerts, combined engine filters and **205-alert overflow**: the visible queue
  remains bounded at 200 while all generated alerts remain in SQLite.
- Desktop **1440px**, tablet **768px**, phones **390/320px**: controls fit without
  page overflow; wide data tables keep their accessible horizontal scroll region.
  Unexpected console/runtime error list is empty in passing runs.

Commands: `npm run typecheck`, `npm run build`,
`.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider` and
`node scripts/verify-monitor.mjs --isolated-api` with `UI_BASE_URL`,
`UI_OUTPUT_DIR` and an optional externally installed Playwright on PATH.
Always create an empty disposable `ALERT_DB` before browser verification: this
script deliberately generates alerts. It is not an application dependency.

## Frozen scope and remaining limitations

**This iteration's Definition of Done: PASSED.** Passing UI behavior, regression
coverage, source hashes and evidence are frozen
after final verification. No detection accuracy or performance benchmark is
refreshed. Raw data, frozen models, detector code and analyst history are checked
against pre-task hashes. Normal build-generated Next type references are restored.

Search/export remain limited to loaded records (200), including while held;
older records remain persisted but are not exposed through new archive UI.
Held state is local to the current page and resets on navigation/reload. The
newer-loaded count is capped by the same browser limit, not a total of all alerts
generated while held. This does not add notifications, acknowledgement/workflows
or server-side alert mutation. Experimental detection-quality limitations remain.

The next incomplete completion-plan task is obtaining a qualifying labelled raw
TLS development cohort, verifying its causal/label contract before any candidate
training. See [encrypted source follow-up](ENCRYPTED_SOURCE_FOLLOWUP.md).
The UI pass does not resolve DGA/DNS or baseline benign-control failures and does
not make the final SIH release READY.

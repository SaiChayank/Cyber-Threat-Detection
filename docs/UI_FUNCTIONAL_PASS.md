# Final functional Monitor pass

Scope: the existing Univect UI, 1 October 2026. No visual identity, detector,
model artifact, backend architecture, dependency manifest, database schema or raw
dataset was changed. The existing React/Next.js implementation was preserved.

## Inspected baseline

Inspected `docs/COMPLETION_PLAN.md`, `docs/FRONTEND.md`, the README, frontend agent
instructions and installed Next.js guides; Monitor components, navigation, theme,
API schemas/service and telemetry/SSE hook; existing replay, upload, SSE and SQLite
integration implementations/tests and their reports. Browser checks use the actual
production website and its same-origin API proxy, with a disposable SQLite database.

The UI acceptance check is successful operation of all requested controls at desktop,
tablet and phone sizes, useful empty/error/reconnect feedback, no permanent horizontal
page overflow, no clipped dialog data, working keyboard focus, no unexpected browser
runtime/console errors, and passing TypeScript/production build.

## Findings and minimal fixes

| Finding before the pass | Behavior after the fix |
|---|---|
| A telemetry failure set `reconnecting`, but a later successful poll did not restore `live` if the SSE connection had stayed open. | Connection status derives from API availability and the actual EventSource state. Last received data is explicitly identified during an API outage. |
| A terminal EventSource remained assigned after a non-200 proxy response; native reconnection could never restart it. | Clear a CLOSED source; the next successful telemetry poll reopens it from the last accepted sequence. Native retries for CONNECTING sources remain intact. |
| Successful telemetry polling silently cleared an incompatible-stream warning. | Separate API/stream errors; only a valid alert clears the stream warning. A stream warning does not disable healthy replay/upload APIs. |
| Empty-state instructions were centered inside the 770px-wide table. At 320px, the heading began around x=327 and was initially offscreen. | Empty, no-match and unavailable states render outside the wide table. Populated results retain horizontal scrolling with a keyboard-focusable region and phone/tablet guidance. |
| Selecting the already-current Next.js hash link after resizing could leave its section offscreen. | In-page links use native anchors, including repeat selections. Cross-page routing retains Next.js links. |
| Full IPv6 addresses could overflow a phone-sized evidence dialog. | Connection addresses and timestamps wrap inside the existing dialog. IDs, evidence, Escape and focus return are preserved. |
| Export confirmation used the current filtered count, which changed as new alerts arrived after download. | Confirmation retains the actual downloaded snapshot count. Export still contains all loaded matches across table pages. |

Files changed: `frontend/src/hooks/use-monitor.ts`, `frontend/src/components/site-nav.tsx`,
`frontend/src/features/monitor/{monitor,alert-feed,alert-detail}.tsx`,
`scripts/verify-monitor.mjs`, `.gitignore`, `docs/FRONTEND.md`,
`docs/COMPLETION_PLAN.md`, this report and `docs/verification/ui-functional-pass.json`.
The browser script supplies regressions for each listed UI defect; backend tests
were rerun unchanged. Measured detector accuracy/throughput before and after is
not applicable because this task does not change or benchmark a detector.

## Reproducible checks

`scripts/verify-monitor.mjs` is a standalone browser regression script. Playwright is
an optional verification tool supplied through `npm exec`; it was not added to the
application dependencies. The script refuses a non-loopback URL, requires the
`--isolated-api` acknowledgement, and refuses an API with existing alert records.
It never deletes or clears records, and it appends controlled replay/fixture alerts
only to the disposable API. Never run it against the analyst database.

Stop any other local API first: the existing launcher intentionally reuses an already
running compatible API. In one PowerShell terminal, from the repository root:

```powershell
npm.cmd run build
$env:ALERT_DB = Join-Path $env:TEMP ('univect-ui-' + [guid]::NewGuid().ToString('N') + '.sqlite3')
npm.cmd start
```

In a second terminal:

```powershell
npm.cmd exec --yes --package=playwright -- node scripts/verify-monitor.mjs --isolated-api
npm.cmd run typecheck
.venv/Scripts/python.exe -m pytest -q
```

The default browser channel is installed Chrome. Set `UI_BROWSER_CHANNEL=msedge`
to select installed Edge, `UI_BASE_URL` for another loopback website port, and
`UI_OUTPUT_DIR` for an alternate artifact directory. By default, results and screenshots
are written to ignored `artifacts/ui-pass/`. Close the disposable service with Ctrl+C
when finished; a normal new terminal uses the project's usual alert database.

## Results

- Production Chromium checks: **20/20 passed**, at 1440×1000, 768×1024, 390×844 and
  320×740 viewports. The retained machine-readable report is
  [ui-functional-pass.json](verification/ui-functional-pass.json).
- Navigation, repeated section selection after resize, mobile menu Escape/focus,
  landing/Monitor routing and reduced-motion operation pass.
- C2 replay begins incrementally, selections disable while running, Stop halts
  processing, and an all-scenario restart completes 256 events. Counters and the
  real chart update; alerts arrive through SSE.
- Combined threat/severity/search filters, no-match recovery, pagination and the
  actual downloaded JSON contents pass. Export includes all filtered loaded records,
  with real IDs/evidence, and its confirmation remains stable as new alerts arrive.
- Alert detail, long IPv6 connections/identifiers, evidence, actual clipboard JSON,
  Escape and restored Inspect-button focus pass across the required sizes.
- The browser's PCAP file input passes extension, empty-file, fake-PCAP, 16 MiB limit,
  truncated-packet replay-error and valid classic Ethernet PCAP checks. The valid
  fixture processes exactly three packets; the next replay succeeds after failure.
- API outage disables replay/upload, renders an unavailable state and supports Retry
  and automatic recovery. A separate SSE outage with a healthy API shows reconnect
  feedback, then receives all three alerts persisted during disconnection with no
  duplicate table sequence records. Stream-schema warnings persist through unrelated
  telemetry polls and clear on a valid event.
- Unexpected browser runtime/console errors: **0**. Expected HTTP errors from the
  deliberately injected outages and invalid uploads are distinguished from app errors.
- `npm run typecheck`: **pass**. `npm run build`: **pass**.
- Full backend suite: **208 passed**, with the existing Starlette TestClient deprecation
  warning. No dependency upgrade was introduced to address that unrelated warning.
- Existing analyst history remains **130 records**; test services used separate temporary
  databases throughout. Raw datasets and frozen model artifacts are untouched.

## Limits and decision

**This task's Definition of Done passes.** The results are functional UI verification,
not detector accuracy or a capture-to-browser throughput/latency measurement. They
do not change the quality or promotion status of any experimental detector.

Automated coverage is Chromium on Windows with resized viewports, not physical
touch devices or Safari/Firefox certification. The current table intentionally scrolls
horizontally on small screens, and filters/export cover the latest 200 loaded records;
SQLite retains the complete history. PCAPNG and unsupported protocol extraction remain
outside the existing capture contract. Initial API outages are injected at the browser
route boundary; SSE recovery uses native EventSource and the real persisted API stream.

Stop here. The next scoped task, after explicit instruction, is phase 6's reproducible
demonstration/package pass: a fresh-checkout setup check, concise demo sequence and
requirement/provenance checklist with the existing unresolved detector limits disclosed.

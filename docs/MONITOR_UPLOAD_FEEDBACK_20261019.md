# Monitor upload-error and recovery verification

19 October 2026 IST; baseline `5261596`. **Scoped DoD: PASS.** Existing frontend
behavior is frozen; no visual identity, component, API or detector change needed.

Inspected ReplayControls, real API service/error parsing, upload route/cleanup,
launcher/proxy configuration and prior storage-failure regressions. The bounded
protocol and isolated process controllers are in
`verification/monitor-feedback-20261019/`.

## Real integration and observations

Used the production Next.js Monitor on loopback 13519 and the actual FastAPI
handlers/pipeline/SQLite on 18519. Both processes were test-owned and used an
ephemeral database/staging directory. A separate test entry point injected ENOSPC
on its first temporary capture allocation only; subsequent allocations used real
filesystem files. No product fault flag, fake route, mock response or new framework
was added. Generated one-packet PCAP/invalid-magic files are transport fixtures,
not research datasets or accuracy observations. No active network packets sent.

The observed browser → proxy → real API sequence is:

1. Empty Monitor loads with connected SSE and zero events/alerts.
2. Valid-file upload encounters the controlled allocation failure: **503**. UI
   displays the generic storage-recovery detail, no internal exception path, and
   releases the upload/replay controls from busy state.
3. Retrying the **same file**: **200**, replay completes with **one event/zero
   alerts**. The input reset permits same-file retry; no reload required.
4. Invalid-magic `.pcap`: **422**, correct unsupported-format feedback appears.
5. Valid-file retry after that rejection: **200**, again one event/zero alerts.

Backend logs confirm upload statuses **[503, 200, 422, 200]**, not inferred solely
from notifications. Final API has no replay error, zero alert records, and no
staged files remain. Both candidates stay disabled. No public-source replay was
started; the existing local preset readiness listing was not an accuracy claim.

Error feedback and usable retry control verified at **1440×1000**, **768×1024**
and **390×844**. Document scroll widths were 1430, 758 and 380 respectively: no
page-width overflow. Mobile retries/malformed recovery also passed. This is a
targeted feedback/responsiveness check, not a renewed full accessibility/device
or every-dashboard-feature audit. Browser console captured **zero warnings/errors**
for this Monitor test flow.

## Scope, freeze and next

Only verification scripts, protocol, screenshots/logs/receipts and this dated
report/pointers were added. No application defect was found in the UI and no
frontend source or new application unit test was needed. The preceding backend
package's 557 passes remain its earlier measurement; no full suite rerun is
claimed here. Production build passed with isolated proxy configuration, then
the normal `.env`/default production build was restored after testing so a later
`npm start` does not retain the stopped test API target.

Stopped owned processes, deleted only their ephemeral test directory and reset
the browser viewport/closed the owned tab. All **130 protected original files**,
including analyst DB/WAL/SHM, models, data and frozen contracts, are unchanged.
No source dataset, reserve, model, threshold, gate or performance metric changed.
Saved fixture paths are evidence of ephemeral files; the controller generates
them anew when reproduced in another verification workspace.

Freeze the working upload feedback/retry behavior and scoped screenshots/results.
This is not final T50/T60 or release acceptance. Required source/intent-quality
blockers remain. Exact next independent package: verify runtime SQLite read-error
responses for alert/history/telemetry/SSE using disposable fault injection, and
fix only a measured failure without losing history or changing valid alert data.

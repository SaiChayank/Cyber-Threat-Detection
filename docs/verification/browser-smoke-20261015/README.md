# Production browser smoke — 15 October 2026

Scope: existing production Next.js build, FastAPI and a dedicated disposable
SQLite database. Analyst history, datasets, models and detector gates unchanged.
Used the verification skill and in-app browser UI controls; did not execute the
standalone Playwright script. Existing script and prior UI report informed cases.

**Result: 32/32 recorded interactive checks passed.** These are browser smoke
assertions, not a replacement for the backend suite or independent accuracy tests.
Backend suite separately passed 377 tests; TypeScript and build separately passed.

Verified empty state/control availability, incremental start, scenario lock, stop,
restart/completion, 256 processed events, alerts appearing before combined replay
completion, chart rendering, threat/severity/engine filters, no-match search/reset,
pagination, evidence/identifiers, filtered JSON export, mobile dialog/Escape focus,
tablet/mobile navigation and bounds at 768/390/320px, queue hold/resume action,
valid classic Ethernet PCAP (3 packet events), malformed PCAP error/recovery,
backend outage warning/disabled controls/retained alerts, restart and subsequent
SSE delivery, duplicate-free history, landing navigation and persistence on return.
Desktop viewport 1440x1000. Temporary viewport overrides reset after verification.

Combined synthetic replay yielded 15 alerts across seven classes. A post-restart
DDoS replay added two alerts. `integration-evidence.json` verifies all 17 exported
records exactly match the API and read-only SQLite query, with unique alert IDs and
sequences 1–17. Original 185 backend/source/artifact hashes remain unchanged.

No captured browser error/warning logs in the collected result. Forced backend
outage intentionally produced proxy HTTP failures and a visible API error;
expected fault-injection failures are not application defects. No code changes or
new regression tests were needed. An initial locator used AX checkbox wording
for the queue control; DOM inspection established its actual button role and
corrected the interaction. This was a test-selector issue, not a UI failure.

Files added: this report, `browser-results.json`, `integration-evidence.json`,
screenshots, controlled valid/invalid PCAP fixtures and exported synthetic alerts
in this evidence directory. No frontend/backend code changes. Servers started
solely for this check are stopped afterward; disposable history remains separate.

Limitations: viewport emulation, not physical devices; no malformed-SSE injection,
full motion/assistive-technology audit, stress/latency benchmark or reserved detector
evaluation. Queue hold/resume control transition verified without generating a
new alert while held. Existing candidate activation states stay unchanged.
All synthetic classes are demonstration output, not real-world accuracy claims.

Definition of Done: scoped functional/responsive smoke passed. Freeze this result;
do not redesign or optimize passed features. Next incomplete detection prerequisite
is DNS-tunnelling source qualification (permissions, joined session truth, five
benign control strata and exact current evaluation contract), documented in
`docs/DNS_TUNNELLING_DATA_GAP.md`. No automatic publisher contact or scoring.

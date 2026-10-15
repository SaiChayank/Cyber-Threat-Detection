# T02 — Clean-checkout installation and demo reproduction

15 October 2026. **Scoped Definition of Done: PASS after the packaging fix.**
Final tested commit: `a12eb48` (parent `db7738e`). This verifies the local committed
snapshot; it does not establish that GitHub has these unpublished commits.
No detector, feature, threshold, model, frozen gate or reserved data changed.

## Scope and environment

Inspected README, final demo guide, root/frontend package manifests and lockfile,
requirements, setup/launcher scripts, checkout tests, model/demo integrity checks,
API/persistence/replay code and the T02 plan before starting. Preregistered scope:
[protocol](verification/clean-checkout-20261015/PROTOCOL.md).

Two separate clones used `git clone --no-local --no-hardlinks --no-checkout` and
`git -c core.autocrlf=true checkout --detach <commit>`. The first tested `db7738e`;
the second tested committed fix `a12eb48`. Each installed its own npm packages and
created its own `.venv` through `npm run dev`. No environment, analyst database,
raw dataset or `.env` was copied from the development project. Normal registry
download caches were allowed; installed dependencies were not borrowed.

Windows, AMD64, Python 3.13.5, Node 22.14.0, npm 11.12.0, Next.js 16.3.6,
TypeScript 5.9.3. Ryzen 7 8845HS, 16 logical CPUs, 16,356,941,824 bytes RAM.
The fresh venv has `include-system-site-packages=false`. Exact resolved Python/npm
versions and command durations are retained in the evidence directory.

## Findings and minimal corrections

1. Initial default startup installed requirements but failed because an unrelated
   service acquired port 8000 and returned 404 for `/api/health`. It was left alone.
   Used the existing README `.env` configuration: `API_PORT=18000`,
   `API_PROXY_URL=http://127.0.0.1:18000`, `WEB_PORT=13000`. Development and production
   startup then passed. README now explains changing API port/proxy together.
2. The committed npm lockfile resolved TypeScript 6.0.3 despite the declared
   `~5.9.3`. `npm ls` reported an invalid compiler (and two extraneous optional
   nodes in that initial install). Corrected only the compiler lock entry using
   the existing declared range. No manifest dependency or application code changed.
   A new checkout regression fails against 6.0.3, passes against 5.9.3. Six packaging
   tests passed before committing the fix as `a12eb48`. A second clean installation
   of that commit has `npm ls --depth=0` exit 0 and `pip check` exit 0.
3. README incorrectly described initial speed as 1x. Source and fresh browser show
   100x selected; corrected the prose. The demo explicitly selected 20x, so frozen
   inputs, alert expectations and detector semantics are unchanged.

There were no undocumented application setup steps beyond this lockfile correction
and the already-supported port override. Test harness polling, logging and process
cleanup are verification operations, not extra application setup requirements.

## Executed checks

- `npm install`: passes in both fresh clones. Final install: 146 packages added,
  148 audited. Two high-severity dependency advisories remain (Next.js and
  source-map-js); report retained, no automatic `npm audit fix` or unrelated upgrade.
- `npm run dev`: automatically creates `.venv`, installs `requirements.txt`, starts
  FastAPI and serves Monitor (HTTP 200) with the documented port configuration.
- `.venv/Scripts/python.exe -m pytest -q`: baseline 442 passed/two skipped;
  corrected checkout **443 passed, two skipped, one warning, 152.28 seconds**.
  Both skips are optional PyArrow research audit tests, not missing demo/runtime
  dependencies. Existing Starlette/httpx deprecation warning remains. PyArrow was
  not installed merely to broaden this base-install verification.
- `.venv/Scripts/python.exe -m replay.demo_pack`: all nine frozen fixtures pass
  provenance, generator, evidence/trace and incremental-position checks.
- `npm run typecheck` and `npm run build`: exit 0 from the corrected checkout.
- `npm start`: starts both production services. `/`, `/monitor`, `/docs` and health
  respond successfully. Browser landing-to-Monitor navigation works.
- All seven model sidecar SHA256 values match. All 79 protected runtime/model
  files compared byte-identically with the original project. The DNS contract is
  exercised by the full suite; no reserved-pass receipt exists.
- `.venv/Scripts/python.exe -m replay.cli data/demo/all.jsonl --speed 20`:
  exit 0, 15 alerts/seven classes, 44.30 seconds in the corrected checkout.

## Production browser, persistence and demo

Used the in-app browser against the corrected production checkout. Fresh Monitor
has zero processed events/alerts and no downloaded public presets; 100x is the
initial selected speed. Explicitly selected ALL at 20x. Replay enters running
state, locks scenario/speed, enables Stop and delivers alerts before completion.
A running screenshot captures 73 processed events and three recorded alerts.

Replay completes with **256 events, 15 unique alerts, seven threat classes** and
no replay error. Proxy API records exactly equal a read-only SQLite query, with
sequences 1–15. Opened an exfiltration alert: confidence, HYBRID source, addresses,
flow/alert IDs and numeric evidence appear, including the synthetic-posterior and
possible-exfiltration limitations. No production accuracy is inferred.

Stopped only the test-owned process tree and restarted `npm start` using the same
clean-checkout database. All 15 records, IDs, ordering and evidence remain equal;
replay state resets to idle/zero processed. Reloaded Monitor shows Stream connected
and 15 matching/15 loaded records. Temporary servers/tab are stopped/closed after
verification; original analyst database/WAL/SHM hashes remain unchanged.

Captured application tab warning/error console before the deliberate restart is
empty. The browser-control runtime separately emitted external Statsig/Cloudflare
telemetry errors; those are not Univect page errors. This check is a desktop demo
smoke, not a repeated full responsive/accessibility/fault-injection audit.

## Fresh scoped performance evidence

Commands are the README defaults, run in the isolated checkout before production
startup. Their generated JSON reports are copied here; original historical reports
in the development repository are not overwritten.

- Core: 20,000 synthetic metadata events, 1,170 alerts, 4.79828 seconds,
  **4,168.16 events/sec**, processing plus SQLite p50 0.1499 ms and **p95 0.9632 ms**.
  Gates >=2,000 events/sec and p95 <50 ms pass. This excludes raw capture,
  HTTP, SSE and browser rendering.
- Delivery: **100/100 successful deterministic API/persisted/SSE alerts**;
  p50 139.4124 ms, **p95 247.4901 ms**, p99 253.8900 ms. Durable persistence
  after API shutdown verified. Gate p95 <1,000 ms passes. This is direct loopback
  API-to-SSE delivery excluding Next.js proxy, browser rendering, capture and
  concurrent subscribers. Browser replay separately verifies functionality.

## Frozen outcome and remaining limitations

Files changed: root lockfile, one packaging regression in
`tests/test_checkout_setup.py`, README setup/default-speed prose, current plan
status, this report and its new evidence. No shared runtime source changed.
Compiler mismatch: invalid 6.0.3 -> valid 5.9.3; deterministic demo remains 15
alerts/seven classes. Test count rises by the single new compiler regression;
this is not a detector accuracy change.

Freeze this setup behavior/regression and measured snapshot. This run establishes
the local Windows demonstration, not Linux/macOS, offline package installation,
security clearance, exact future Python dependency resolution or public-data
generalization. Optional research checks remain skipped. Two high npm advisories,
unpublished commits and existing detector/data-quality release blockers remain.
No training, reserve consumption or candidate activation occurred.

**Next incomplete independent task: T20**, one subtype's observability and smallest
next-experiment decision, starting with UDP flooding. Do not implement or tune that
experiment as part of T02. Data-dependent DGA/DNS/TLS tasks remain separately blocked.

Evidence: [verification directory](verification/clean-checkout-20261015/), including
command logs, initial failures, package inventories, model/integrity hashes,
demo/API/SQLite/restart results, screenshots and benchmark JSON. The final freeze
manifest pins raw report/evidence bytes. No commit or push of raw datasets/databases.

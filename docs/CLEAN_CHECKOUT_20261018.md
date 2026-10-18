# Current-baseline clean-checkout checkpoint

18 October 2026 IST. Tested local commit **`4e92b3b`**. Installation, tests,
build, scoped performance and the controlled browser replay pass. **The complete
rehearsal DoD remains PARTIAL: this run did not repeat the restart check.**
Final T60 and release readiness remain blocked on detector-quality work.

Inspected README, root/workspace manifests and lockfile, requirements, launcher,
prior clean-checkout report, models/demo checksums, replay/API/SSE and SQLite code.
The [protocol](verification/clean-checkout-20261018/PROTOCOL.md) was written before
installation. No production code, requirements, model, rule, gate or dataset was
changed. Only evidence-local controllers, logs, observations and dated status
documentation were added. No new application tests or defect fixes were needed.

## Environment and isolation

Cloned the local committed repository using `--no-local --no-hardlinks
--no-checkout`, then checked out with `core.autocrlf=true`. New directory:
`C:/Users/Saich/AppData/Local/Temp/univect-clean-20261018-4e92b3b`.
No developer venv, node_modules, .env, raw data or analyst database was copied.
Registry download caches were allowed. The documented .env override selected
API port 18418 and website port 13418. Python 3.13.5, Node 22.14.0, npm 11.12.0,
Next.js 16.3.8, TypeScript 5.9.3, Windows AMD64. The fresh venv explicitly disables
system site packages. Exact package versions and commands are saved with evidence.

## Executed results

- `npm install`: 146 packages added, 148 audited, zero reported vulnerabilities.
  This is the installer result, not a comprehensive security clearance.
- `npm run dev`: created its own venv, installed requirements, started FastAPI and
  served Monitor successfully. `pip check` and `npm ls --depth=0` passed.
- Backend suite: **531 passed, 3 skipped, one warning, 145.83 seconds**. Two skips
  are optional PyArrow research checks; one is the optional UMA decoder module
  absent from base dependencies. Its eight cases separately passed in the source
  environment. The existing Starlette/httpx deprecation warning remains.
- Demo-pack verification: passed all nine fixtures. All seven model hashes match;
  checked DGA/DNS frozen contracts match source bytes. No retraining or scoring.
- `npm run typecheck`, `npm run build`, `npm start`: passed. Landing navigation to
  Monitor worked, the empty state and connected stream appeared, and the production
  page showed the newly generated scoped benchmark correctly.
- README offline demo command at 20x completed, producing 15 alerts/seven classes.
- Controlled UI-triggered ALL replay at 20x: **256 events, 15 unique alerts/seven
  classes**; alerts arrived while running, before completion. API, proxy SSE and
  read-only SQLite records matched exactly. See `demo-integration.json`.
- Later browser observation showed **30 historical records** and speed 100x.
  A subsequent run occurred after the controlled observer completed; its actor
  and timing were not observed. Original controlled 15 records remain identical.
  Do not present the later screenshot as the controlled 15-alert endpoint or
  interpret new alert IDs as duplicate SSE delivery. The actual 30-record snapshot
  is preserved in `pre-restart-history.json`; no history was cleared.
- Browser console: zero captured application errors, two Three.js shader precision
  warnings across landing visits. No full responsive/fault-injection audit repeated.

## Scoped performance

Ryzen 7 8845HS, 16 logical CPUs, 16,356,941,824 bytes RAM, Python 3.13.5.
README benchmark commands ran in the fresh checkout with disposable databases:

- Core: 20,000 synthetic metadata events, 1,170 alerts, 5.75777 seconds;
  **3,473.57 events/sec**, processing + SQLite p50 **0.2043 ms**, p95 **0.9922 ms**.
  Gates >=2,000 events/sec and p95 <50 ms pass. Excludes capture, HTTP, SSE and UI.
- Loopback delivery: **100/100** API/persisted/SSE alerts, p50 **143.9397 ms**,
  p95 **245.8072 ms**, p99 **253.0494 ms**; gate <1,000 ms passes. Durable state and
  sequence resume checks pass in the benchmark. Excludes proxy/browser/capture.

The older 15 October rehearsal measured 4,168.16 events/sec, core p95 0.9632 ms,
delivery p95 247.4901 ms. These are different runs, not a controlled optimization
comparison; both meet the scoped gates. Detection accuracy was not reevaluated.
Reports are retained in this dated evidence directory; original benchmark reports
and historical frozen results were not overwritten.

## Limitations, freeze and next step

The five-hour unattended window elapsed during the interruption before this
checkpoint. Restart persistence was **not repeated in this rehearsal**; the older
passed restart evidence remains historical. The unused `restart` helper requires
an empty-history controlled replay and is not evidence of an executed test.
Stopped only the confirmed test-owned launcher process tree and closed the owned
browser tab. The temporary checkout and its 30-record database remain available;
the original project database/WAL/SHM and protected artifacts are unchanged.

No undocumented setup failure was found. Freeze the executed results and their
scope; do not label the full rehearsal or release complete. Exact next task:
finish the isolated restart comparison against the saved 30-record snapshot,
verifying unchanged IDs/order/evidence and fresh idle runtime state. No new
detector experiment, model promotion, email or push is authorized by this report.

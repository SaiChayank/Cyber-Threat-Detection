# Current-runtime clean-checkout rehearsal

20 October 2026, Asia/Calcutta. Tested local commit **`f380837`**.
**Rehearsal DoD: PASS. Final release: NOT READY; detector-quality/data gates
remain unresolved.** This rehearsal includes the committed replay-error and
stored-JSON recovery fixes. It does not reopen frozen detector experiments.

## Inspected, environment and setup

Reviewed README, .env.example, package scripts, Python launcher, prior clean
checkpoint/restart observers and artifact checks. The
[protocol](verification/clean-checkout-20261020/PROTOCOL.md) froze this check before
installation. Reused the existing evidence controller with new paths/ports;
no application architecture, code, test or dependency changed.

New directory: `C:/Users/Saich/AppData/Local/Temp/univect-clean-20261020-f380837`.
Cloned committed local Git state with `--no-local --no-hardlinks --no-checkout`,
then checked out with `core.autocrlf=true`. This verifies the current unpublished
local commit, not that the remote repository already contains it.

No developer venv, node_modules, .env, raw datasets or analyst history was copied.
Only the README-documented .env port override selected API 18420 and website
13420. `npm install` installed 146 packages and reported zero vulnerabilities;
that installer output is not a full security clearance. `npm run dev` created
its own venv, installed requirements, started the API and served Monitor.
No undocumented setup fix was necessary.

System prerequisites: Windows AMD64, Python 3.13.5, Node 22.14.0, npm 11.12.0;
Next.js 16.3.8 and TypeScript 5.9.3. Registry caches were allowed; installed
packages and exact command receipts are saved. System site packages were disabled
in the new venv. Other operating systems/Python versions were not tested here.

## Tests, build and hashes

- `pip check`, `npm ls --depth=0`, `npm run typecheck`, `npm run build` and
  `npm start` pass. Production served the same-origin Monitor/API/SSE path.
- Fresh base-environment backend run: **606 passed, 3 skip reports, 1 warning in
  124.81 seconds**. Two individual PyArrow research tests skip, and the optional
  UMA tooling module skips eight cases because its research dependencies are not
  in base requirements. These explain the difference from the preceding source
  environment's **616 passes**. No runtime test failed. Existing Starlette/httpx
  deprecation warning remains; no unrelated dependency was added to hide it.
- All **seven model hashes** and both checked DGA/DNS frozen contracts match
  the source bytes/sidecars. No retraining, scoring or activation occurs.
- Demo preflight passes all nine complete frozen traces. The README offline
  ALL replay at 20x completes with 15 alerts/seven classes.
- The clean checkout's only tracked modifications are the two documented
  benchmark outputs created by their actual commands. No setup patch is applied.

## Production demo and restart

The browser starts with an empty queue and connected stream. Selected ALL and
20x and used the actual Start replay button. The controlled replay processes
**256 events**, persists **15 unique alerts/seven classes**, and completes.
First API observation with an alert is at event **39**, while replay is running;
this polling position is not an exact detector trigger index or latency measure.
The running browser screenshot independently shows alerts before completion.

All full proxy-SSE records match API records and read-only SQLite rows exactly.
The detail dialog displays source/destination, captured time, identifiers, lexical
evidence and the synthetic-trained score basis. Public presets correctly remain
unavailable in a checkout without research datasets; the bundled fallback works.

After stopping the verified owned production tree, a second `npm start` preserves
all **15 identical records**. Runtime telemetry resets to idle/zero processed,
and Last-Event-ID 7 resumes exactly sequences 8-15 with **eight unique records**.
Browser reload shows the connected stream and retained 15-alert queue. An initial
exact-text locator timed out; the fresh DOM confirmed the connected status and
the status-region locator passed. This was a verification locator issue, not a
setup workaround or application failure. Captured console: **zero errors and
zero warnings** for this Monitor replay/reload scope.

Stopped only the owned development/production/restart trees; both selected ports
are released. Closed only the temporary verification tab. The isolated checkout
and its 15-record database remain intact. No unrelated service was stopped, and
the developer's existing running application was not silently replaced.

## Scoped performance

Ryzen 7 8845HS, 16 logical CPUs, 16,356,941,824 bytes RAM, Python 3.13.5.
README benchmark commands ran sequentially with disposable benchmark databases:

- Core: **20,000 metadata events**, **1,170 alerts**, **4.698178 seconds**,
  **4,256.97 events/sec**, processing + SQLite p50 **0.1634 ms**, p95 **0.8938 ms**.
  Gates >=2,000/sec and p95 <50 ms pass. Excludes capture, HTTP, SSE and browser.
- Direct loopback delivery: **100/100** exact API/persisted/SSE alerts, p50
  **141.75 ms**, p95 **246.11 ms**, p99 **258.84 ms**. Gate p95 <1,000 ms passes;
  durable reopen/resume checks pass. Excludes capture, Next.js proxy, browser
  rendering and concurrent subscribers. The separate live production check above
  verifies correctness through the proxy, without measuring its latency.

The prior source-environment run measured 3,955.74/sec, core p95 0.9790 ms and
delivery p95 249.29 ms. Differences are run/environment variation, not optimization
or a controlled before/after comparison. Root canonical benchmark reports are
preserved; this rehearsal retains separate results with runtime source hashes.

## Files, freeze, limitations and next

Only README/current-plan pointers, this report and its new verification scripts,
logs, screenshots and checks change. New task-local text receipts normalize to
LF for Git; exact original receipt bytes/SHA256 are retained under ignored
`data/raw/clean-checkout-evidence-originals-20261020/`. All **130 current protected
source files match**, including original analyst DB/WAL/SHM, raw inputs and gates.
No existing test was added/changed because no setup defect was found.

[Executed commands, environment, tests/build, live comparison, restart, proof and freeze](verification/clean-checkout-20261020/)
support this Windows/local-commit rehearsal. It is not a public-data accuracy test,
remote-clone publication check, full mobile/fault audit or final T60 acceptance.
Required DGA, DNS, UDP/C2/spoof and encrypted generalization limits remain.

Freeze this passed rehearsal and the current runtime behavior. **Exactly next:**
inspect the frontend alert contract and test malformed alert responses through
the existing Monitor integration boundary using disposable state. Make a change
only if that later integration exposes a real defect; do not refactor a passed
component or broaden detector scope. Research source qualification remains a
separate blocked track, with no model experiment authorized by this rehearsal.

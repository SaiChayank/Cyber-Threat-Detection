# Dependency security triage and minimal remediation

16 October 2026; inspected baseline `e2a34b9`.
**Scoped Definition of Done: PASS. Overall release remains NOT READY.**
This closes the two npm dependency findings retained by the 15 October clean
checkout; it does not replace that historical report or complete final T50.

## Inspected and root finding

Reviewed both package manifests/lockfile, the previous audit, installed dependency
tree, frontend AGENTS instructions and bundled Next upgrade guide, Next config and
App Router files, frontend API/SSE/replay consumers, launcher, checkout tests and
producer advisories/patches. Fresh `npm audit --json` reproduced two high-severity
package findings containing seven individual advisory entries. Installed versions
were Next.js 16.3.6 and source-map-js 1.2.1, not a mocked frontend response.

Reachability is distinct from package vulnerability:

- [Draft/cache leak](https://github.com/vercel/next.js/security/advisories/GHSA-3w37-wq28-93x7):
  no Cache Components/use-cache or Draft Mode preview paths were found.
- [Pages SSG/ISR poisoning](https://github.com/vercel/next.js/security/advisories/GHSA-4jqv-mc3x-m676):
  this project uses App Router, not Pages Router SSG/ISR.
- [Development MCP disclosure](https://github.com/vercel/next.js/security/advisories/GHSA-39w2-rjm5-chcv):
  relevant to the supported `npm run dev` workflow. Loopback binding does not
  establish protection from browser-origin disclosure. Not a production endpoint.
- [Metadata image bypass](https://github.com/vercel/next.js/security/advisories/GHSA-f87g-xv8r-7p7x):
  no corresponding dynamic metadata-image routes or webpack configuration found.
- [Catch-all cache poisoning](https://github.com/vercel/next.js/security/advisories/GHSA-mcj8-r9mp-w47p):
  no root catch-all page; current app routes are `/` and `/monitor`.
- [Image SSRF](https://github.com/vercel/next.js/security/advisories/GHSA-cjq9-62q9-8jv4):
  no `images.remotePatterns` or next/image imports. The publisher explicitly
  excludes applications without remotePatterns from this particular issue.
- [source-map-js producer fix](https://github.com/7rulnik/source-map-js/commit/cf76580)
  and [release 1.2.2](https://github.com/7rulnik/source-map-js/releases/tag/v1.2.2):
  Tailwind/PostCSS and Next resolve this library transitively. No application
  source-map input endpoint was found; public exploitability here is unproven.
  Invalid indexed offsets were accepted by the old constructor. No expensive
  malicious-map serialization or attacker-controlled upload was executed.

Next's publisher pages showed placeholder patch labels `16.3.?`; the exact 16.3.8
selection uses the fresh registry advisory ranges, exact-version registry metadata
and successful post-update audit. Do not present the placeholder pages as exact
patch-version confirmation. Machine-readable triage records all seven entries.

## Minimal changes

- `frontend/package.json`: Next minimum `^16.3.0` -> `^16.3.8`; other declarations
  and original ordering retained.
- Root lockfile: Next 16.3.6 -> 16.3.8 plus its required @next/env and eight platform
  SWC entries; source-map-js 1.2.1 -> 1.2.2 inside parents' existing `^1.2.1` range.
  No package added/removed, unrelated update, override, major upgrade or force fix.
- `tests/test_checkout_setup.py`: three regression cases prevent the known unsafe
  declared Next floor and vulnerable lock resolutions, including nested installs.
- `scripts/verify-dependency-security.mjs`: four built-in Node tests cover excessive,
  nested-total and invalid numeric indexed offsets, plus valid mapping preservation.
  No test framework/dependency added. Request/alert/UI implementation is unchanged.

Commands used: `npm install --workspace frontend next@16.3.8 --save-prefix '^'
--package-lock-only --ignore-scripts`, then `npm update source-map-js
--package-lock-only --ignore-scripts`, then `npm ci --ignore-scripts`. This is a
fresh node_modules install from the updated lock, not another fresh Python clone.

## Tests and measured before/after results

- Audit: **2 high-severity vulnerable packages / 7 advisory entries -> 0 known npm
  advisories**. Both reports and exact package tree/registry integrity are saved.
- Before update, all three new Python packaging checks fail. The three negative
  Node security checks fail and the benign mapping check passes. An initial benign
  test used an unsuitable indexed lookup assertion; it was corrected to mapping
  iteration and rerun against the old package **before** updating. Both logs remain.
- After update: **9 packaging tests pass; 4 Node security tests pass**.
- Entire backend suite: **455 passed**, one existing Starlette/httpx deprecation
  warning, 151.19 seconds. Unlike the earlier fresh base environment, this existing
  venv runs the optional research checks too; no dependency was added for them.
- `npm ls --depth=0`, `npm run typecheck`, `npm run build`: pass. Build uses Next
  16.3.8/Turbopack. A second normal-config production build restores the developer's
  ordinary proxy configuration after the isolated smoke build; no `.env` edits.

## Application non-regression

Story: landing -> Monitor -> existing synthetic replay -> proxied API -> detector
-> disposable SQLite -> proxied SSE -> rendered alerts and supporting evidence.

Production smoke used test-only loopback ports 13465/18465 and a unique TEMP
database. Landing, Monitor and direct/proxied health return 200. The browser starts
the default ALL replay at 100x: **256 synthetic events / 15 unique alerts across
seven labels**. An intermediate API checkpoint records 125 events and six alerts
while still running. All 15 API, SQLite and proxied SSE records match exactly,
including sequence/IDs/evidence. Monitor shows 15 loaded records and an accessible
investigation dialog with synthetic-posterior and possible-exfiltration caveats.
This is integration evidence, not independent detector accuracy or a new benchmark.

Browser console capture: **zero errors**, one Three.js shader floating-point
precision warning. No shader/UI redesign was undertaken. The connection wait's
first exact-text selector was too strict because the status includes extra text;
the role/status selector verified the already connected UI. No application fix
was needed for this harness issue. Test-owned servers and tab were stopped/closed;
unrelated services and the user's Gmail tab were left alone. Automatic approval
review blocked a background Start-Process launch with reason `blocked by policy`;
managed foreground terminal sessions completed the same test safely.

## Preservation, freeze and limits

124 before/after raw-byte pins verify runtime sources, model artifacts, relevant
data/contracts, requirements and the original alert database/WAL/SHM unchanged.
No raw dataset or reserved evaluation was inspected, no model trained/promoted,
no gate changed. Existing failed candidates and required-quality blockers remain.
No core/API-to-SSE benchmark was rerun; UI performance samples/saved benchmark
panels do not refresh those reports. No overall security/production readiness claim.

Evidence is Windows/Node 22.14.0/npm 11.12.0/Python 3.13.5 and the local test venv.
New text logs normalize line endings/trailing whitespace only; failed checks remain.
Linux/macOS, public hosting, Python/OS vulnerability scanning, exhaustive Next
exploit reproduction and a final post-integration clean checkout are outside scope.
Registry advisories can change: zero is a dated finding, not permanent safety.

Freeze this patch/test/lockfile evidence without further cleanup. Next eligible
independent task is the C2 observability decision using existing development
failure evidence, only when explicitly authorized. UDP/DGA/DNS/TLS source tracks
remain blocked; final T50 and release audit still follow accepted integrations.

Evidence: [protocol](verification/dependency-security-20261016/PROTOCOL.md),
[triage](verification/dependency-security-20261016/advisory-triage.json),
[audit before](verification/dependency-security-20261016/audit-before.json),
[audit after](verification/dependency-security-20261016/audit-after.json),
[lock delta](verification/dependency-security-20261016/lock-delta.json),
[smoke](verification/dependency-security-20261016/smoke-result.json),
[integrity](verification/dependency-security-20261016/integrity.json) and adjacent
test/build/browser evidence.

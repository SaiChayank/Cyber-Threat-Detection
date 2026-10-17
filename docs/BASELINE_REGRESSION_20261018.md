# Current-baseline regression — 18 October 2026 IST

**PASS for this verification package; release remains NOT READY.** Baseline
`ee8f72d93c599453b9dc4f70a7708e3e1161083d`, after the C2/spoof/recon/exfil diagnostic
extensions. This is current-baseline non-regression evidence, not final T50/T60
closure, independent threat accuracy, capture-to-browser performance or a demo run.

## Executed

- `.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider`: **533 passed**,
  one warning, **184.22s**. Existing warning: Starlette/httpx TestClient deprecation.
  No dependency is changed merely to hide that warning.
- Root `npm run typecheck`: exit 0; forwards to frontend `tsc --noEmit`.
- Root `npm run build`: exit 0 through the documented launcher. Next.js **16.3.8**,
  optimized build and TypeScript pass; static `/`, `/_not-found`, `/monitor` routes
  generated. No browser/server startup or console check is claimed by a build.

The full suite includes the 46 new recon/exfil cases and previously added C2/spoof
diagnostics. Test count differs from the older 455-test run because those earlier
diagnostic additions had only targeted runs at that point. Do not relabel 533
passing tests as a new model confusion matrix or quality promotion.

## Inspected, preservation and limits

Reviewed root/frontend package manifests, root workspace lockfile, README commands,
Python requirements and current diagnostic commits. Before commands, source/model/
protocol/alert-history and package/config hashes were pinned. After commands,
protected hashes are compared byte-for-byte in the evidence package. Raw source
archives are not inputs to these tests and were not extracted or scored. Existing
SQLite/WAL/SHM and model artifacts are preserved. No application code, feature,
rule, candidate, threshold, dataset role or gate changes in this package.

Evidence: `verification/baseline-regression-20261018/` contains the preregistered
command/source plan, complete backend/typecheck/build logs and integrity/freeze
records. Initial command probes guessed non-existent frontend lock/config paths;
`rg --files` established the root lockfile and actual app paths. A piped
collection-only progress probe closed stdout early under PowerShell, producing
an OSError in that probe; it was not the full test run. The separately captured
full suite completed normally with exit 0. No workaround was needed for the
application's documented setup/build commands.

No new code/test was required to fix a product failure. No fresh independent
quality, performance, authentication/deployment or production-readiness claim is
made. Original data/provenance and passive observability limitations remain.

**DoD:** current full regression/typecheck/build pass with protected-state integrity.
Next eligible task: a separately frozen bounded header-only archive transport check
using the already-installed dataset-tooling decoder for ZIP method 9. No new
dependency or PCAPNG runtime support; no packet/query values or scoring.

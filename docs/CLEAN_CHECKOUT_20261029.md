# Clean-checkout rehearsal, 29 October 2026

Fresh `git clone --no-local` of local commit `3af7f0f` (not pushed) into an empty
folder on Windows 11, Python 3.13, Node 24.22.1. No `.venv`, `node_modules`,
`.env`, raw datasets or analyst database existed beforehand.

| Step | Result |
| --- | --- |
| New venv + `pip install -r requirements.txt` | Succeeded |
| `pytest -q` | 728 passed, 3 skipped (optional research-tool tests), 1 existing deprecation warning |
| `python -m replay.demo_pack` | passed; all nine frozen demo traces match |
| `npm ci` | Succeeded; 0 vulnerabilities (next 16.4.3, zod 4.6.7) |
| `npm run typecheck` | Passed |
| `node --test tests/frontend/monitor-alert-recovery.test.cjs` | 3 passed |
| `npm run build --workspace frontend` | Passed |

Scope: install, tests, demo preflight, typecheck and production build only. The
live dashboard replay, restart persistence and browser checks were not repeated
here; they were last verified in [CLEAN_CHECKOUT_20261020.md](CLEAN_CHECKOUT_20261020.md)
before the P0-3/P0-4/P1-1/P1-2 changes. Detector-quality gates are unchanged and
final release remains NOT READY (see [Model report](MODEL_REPORT.md)).

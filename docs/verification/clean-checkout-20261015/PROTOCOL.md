# T02 clean-checkout verification

Frozen before application startup, 15 October 2026. Test commit `db7738e`
using a separate `git clone --no-local --no-hardlinks` checkout with
`core.autocrlf=true`. Install npm and Python dependencies from the README.
Do not copy environments, raw datasets, `.env` or the analyst database.

Required checks: automatic Python setup via `npm run dev`, empty/new SQLite,
health and frontend startup, frozen demo/model hashes, full backend pytest,
TypeScript, production build/start, Monitor replay at 20x, incremental alerts,
15 persisted alerts/seven classes after 256 events, restart history, documented
offline demo and both benchmark commands. Record failures and setup-only fixes;
no model training, activation, detector change or reserved evaluation.

Existing package download caches may be used; installed packages must belong to
the new checkout/environment. This is a Windows test with the available system
Python/Node/Git, not an air-gapped installation or a Linux compatibility claim.
Dependency advisories are recorded without automatic upgrades.

Use disposable checkout data; preserve original source/artifacts/history. Do not
overwrite historical benchmark reports in the original repository. Browser checks
use the production server from the clean checkout. Stop test-owned servers after
verification. Freeze results and commit this task separately.

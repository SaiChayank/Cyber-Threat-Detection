# Installed backend dependency security triage

20 October 2026 IST; baseline `273d395`. **Scoped DoD PASS; no upgrade required
by this scan.** No runtime, requirement, lockfile, model or detector change.

Inspected requirements.txt, local launcher/imports, prior npm triage and installed
Python metadata. Resolved all five declared roots and applicable transitive markers:
**22 installed PyPI packages**, including pytest and its test dependencies.
Exact versions include FastAPI 0.141.1, Starlette 1.7.0, Uvicorn 0.54.0,
Pydantic 2.13.5, httpx 0.28.1 and pytest 9.1.1; full edges/versions are in the
[inventory](verification/python-dependency-security-20261020/inventory.json).

The [documented OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)
was queried by PyPI name and exact version: **22 complete results, zero returned
advisory IDs**, no pagination. Failed/missing responses are errors, not negatives.
Independent exact-release PyPI metadata checks confirm all 22 versions exist,
have non-yanked distributions available and list no version-specific advisory.
This verifies release availability, not installed-wheel byte integrity.

`pip check` exits zero: `No broken requirements found.` It covers installed
environment consistency, distinct from advisory coverage. All 130 current protected
hashes match, including original history, raw/artifact/gate files. No installation,
dependency addition, code execution from a publisher or API secret was required;
only public package names and versions were sent to advisory/registry endpoints.

Changed only this report, reproducible audit/publisher checks, metadata receipts
and plan/progress pointers. No application tests added/rerun and no fresh build:
runtime behavior is unchanged. Prior source-matching 593-test/typecheck/build and
Monitor evidence remain separately dated. Before/after advisories: no pre-patch
finding or remediation; zero is a current bounded scan result, not improvement.

Reproduction: use the existing venv to run `audit.py`, then
`verify_publishers.py` in the [evidence directory](verification/python-dependency-security-20261020/).
They refuse overwriting historical receipts; copy to a new dated evidence directory
for a new run and preserve its repository-root resolution. No new project package.

**Limitations:** this does not scan Python itself, Windows, optional research
dependencies, all historical versions allowed by broad requirement ranges, npm,
native libraries or application logic. Registry/advisory knowledge changes.
No overall production security or release-ready claim. The existing Starlette/
httpx deprecation warning is retained; no unrelated migration to httpx2.

Freeze the inventory, complete queries, producer cross-check, consistency result
and zero-change decision. **Exactly next:** refresh the declared core + SQLite and
direct API-to-SSE benchmarks on the current source, in disposable stores, with
their original gates and explicit exclusions. This is scoped evidence while data
qualification remains unresolved, not a final-release benchmark declaration.

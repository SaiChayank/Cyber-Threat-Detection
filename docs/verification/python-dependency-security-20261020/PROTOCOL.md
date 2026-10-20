# Backend dependency security triage

20 October 2026 IST, baseline `273d395`. Inspect the installed Python dependency
closure required by requirements.txt, including test dependencies identified as
such. Match environment markers and verify installed versions satisfy their
requirements. Query OSV's documented PyPI exact-version API; never treat network
failure, pagination or missing results as zero advisories. Fetch actual records
for any returned IDs and inspect producer affected/fixed ranges and reachability
before remediation. No broad upgrades or new project dependency.

Only public package names/versions are sent to the advisory API. No project files,
environment secrets, dataset values, models or alert history are transmitted.
This is not OS/Python interpreter scanning, exhaustive application security or
proof that broad requirement lower bounds exclude every vulnerable version.

DoD: reproducible inventory/query/response and pip-check receipts; each finding
triaged or expressly unresolved; minimal necessary fix with regressions if one
is demonstrated. No behavior change if no relevant remediation is established.
Preserve current runtime/models/gates, historical reports and current 130 pins.
No application regression/build rerun needed for a read-only zero-change scan.

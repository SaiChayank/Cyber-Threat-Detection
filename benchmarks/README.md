# Saved benchmark evidence

**3 October recovery follow-up:** newer scoped reports live under
`docs/verification/event-recovery-20261003/`; see
[event recovery validation](../docs/EVENT_RECOVERY_VALIDATION.md). Earlier reports
below are historical, and their source hashes no longer match the changed runtime.
Both runners accept `--output PATH` to record scoped runs without overwriting them.

Documentation audited 2 October 2026; no timing run was performed for this audit.
The two JSON reports retain exact measured numbers, dates and source hashes.

A later clean-checkout release audit saved new reports separately under
`docs/verification/release-audit/`: core 6,248.12 events/s/p95 0.8070 ms and
direct API-to-SSE100/100 alerts/p95 247.48 ms. The standard JSON files below
were preserved. [Final release audit](../docs/FINAL_RELEASE_AUDIT.md) records
the new run's hashes/scopes and unresolved detector-quality blockers.

| File / measured date | Workload and result | Scope |
| --- | --- | --- |
| `latest.json`,1 Oct12:10:58 UTC |20,000 metadata events,1,170 alert commits;3.539879s,5,649.91 events/s; processing+commit p50 0.0971 ms, p95 0.8416 ms | Core+SQLite. Excludes capture, HTTP, SSE, Next.js and browser. >=2,000/s and p95<50 ms pass. |
| `delivery_latest.json`,1 Oct12:11:03 UTC |100 accepted/persisted/delivered;0.509684s serial batch; API-to-SSE p50 129.06 ms, p95 240.27 ms, p99 251.66 ms | Direct loopback API→SQLite→SSE. Excludes capture, Next.js proxy, browser rendering and concurrent subscribers. p95<1,000 ms passes. |

Both recorded runtime/model/script hash sets matched the 2 October audited source. Hardware is
AMD Ryzen 7 8845HS,16 logical CPUs,16,356,941,824 bytes OS-visible RAM; Python 3.13.5,
Windows 11 build 26300. These are one-machine runs, not deployment capacity/accuracy.
The delivery batch rate 196.20/s is informational, not sustained HTTP capacity.

Run from an installed checkout using the README commands:

```powershell
.venv/Scripts/python.exe -m benchmarks.run --events 20000
.venv/Scripts/python.exe -m benchmarks.delivery --events 100
```

Each command uses disposable SQLite and overwrites only its own saved report.
Avoid other heavy work during measurements. Do not copy an old throughput value
into a new report, rewrite its source hashes to imply rerunning, or label the core
benchmark capture-to-browser. Full method/percentile/hardware details and historical
comparison are in [Performance validation](../docs/PERFORMANCE_VALIDATION.md).

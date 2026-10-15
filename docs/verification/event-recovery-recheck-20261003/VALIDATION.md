# Recovery revalidation — 3 October 2026

**Result: PASS for the existing single-process recovery Definition of Done.**
No application/test code changed. Previous frozen evidence remains unchanged.

| Check | Result |
| --- | --- |
| Recovery regressions | 16 passed |
| Full backend suite | 268 passed, 0 failures/skips; 78.54 s |
| Additional probes | 3 passed: SQLite commit failure; full TCP/UDP target LRU rollback |
| TypeScript / production build | Passed |
| Frozen demo | 9/9 traces passed; benign zero alerts |
| Model checksums | 7/7 valid; failed candidates disabled |
| Protected files | 69 unchanged, including analyst DB, model/demo/data metadata and Git index |
| Core + SQLite | 3114.30 events/s; 20,000 events / 1,170 alerts |
| Core + SQLite p50 / p95 | 0.2239 / 1.1085 ms |
| API-to-SSE | 100/100 matching records, durable persistence and resume verified |
| API-to-SSE p50 / p95 / p99 | 150.87 / 246.81 / 259.01 ms |

All unchanged gates pass: core >=2,000 metadata events/s, processing+SQLite
p95 <50 ms, loopback API-to-SSE p95 <1,000 ms. Current core throughput is lower
than the previous 4,072.43/s run, with identical source hashes; the cause of timing
variation was not measured. Both results are retained, without tuning or reruns
to improve the numbers. Hardware/runtime are pinned in the benchmark JSON files.

Core excludes capture/HTTP/SSE/browser. API-to-SSE excludes Next.js/capture/browser
and concurrent subscribers. No generalization accuracy or fault-mode latency claim.
One existing Starlette/httpx deprecation warning remains.

Inspection covered the recovery implementation, tests and saved evidence. Failure
injection confirmed unchanged committed state, atomic rollback and correct retry
accounting/delivery. Files added are only this verification directory's report,
logs and measurements. No tests were added/changed and no new defect was found.

Limits remain: retry before later accepted timestamps, existing SQLite lock timeout,
no durable raw-event queue, in-memory restart state. Browser responsiveness/fresh
installation were not rerun. Overall release remains NOT READY because detector
quality is unresolved. Freeze remains in effect.

Next: training/runtime feature parity diagnosis only, not started.

[Machine-readable results and hashes](report.json).

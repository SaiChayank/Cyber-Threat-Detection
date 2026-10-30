# Performance, 30 October 2026

Evidence: `docs/verification/performance-20261030/`. One machine (Ryzen 7 8845HS, Windows 11, Python 3.13),
quiet, one process. These supersede the thin-margin figures recorded earlier the same day.

| Measurement | Result | Gate |
| --- | --- | --- |
| Core: 20,000 synthetic metadata events through the pipeline with SQLite alert commits (3 runs) | **5,025 / 5,457 / 5,375 events/s**, processing + SQLite p95 **0.33-0.34 ms**, 2,166 alerts | >= 2,000 events/s, p95 < 50 ms |
| Delivery: 100 alerts API -> SQLite -> SSE (3 runs) | 100/100 accepted, persisted and delivered; API-to-SSE p95 **245-250 ms** (p99 253-259 ms); API acceptance p95 4.5-4.9 ms | p95 < 1,000 ms |
| Full PCAP path: 50,000 benign packets, 3,091 flows | **2,435 packets/s**, 150 flows/s, 14.6 Mbps | (stated target) |

## What changed

The SQLite alert store ran in WAL mode with SQLite's default `synchronous=FULL`, which syncs the disk on every
alert commit. It now uses `synchronous=NORMAL` (WAL's standard setting). A same-process A/B with identical
alerts measured **FULL 2,532-2,831 events/s, p95 1.25-1.32 ms against NORMAL 3,237-3,787 events/s, p95 0.44-0.49 ms**
(and 5,000+ on the quiet re-run above).

**Durability trade-off, stated plainly:** a committed alert still survives an application crash or restart (the
delivery benchmark kills the server and verifies every record afterwards) and the database is never corrupted.
Only an operating-system crash or power loss can lose the last few commits. A failed multi-alert batch still
rolls back atomically (`tests/test_store_durability.py`).

## Benchmark bug fixed

`benchmarks/delivery.py` terminated the API server and immediately reopened its WAL database, which on Windows
can hit a transient "disk I/O error" while the dead process's file locks linger (reproduced with the unchanged
store, so it was not caused by this change). It now retries the reopen for up to 10 s and tolerates temporary-
directory cleanup errors.

## Caveats

The core benchmark repeats its scenarios on a fixed schedule, which the slow-beacon tracker correctly treats as
periodic contact, so it raises about twice the alerts it did before that detector (2,166 vs 1,170). Numbers vary
about +/-10-30% with machine load (earlier loaded runs: 2,000-2,700 events/s). These are synthetic one-machine
results, not field throughput.

# Replay control validation

Run `python -m pytest tests/test_replay_controls.py -q`. Tests use isolated
temporary SQLite files and synthetic metadata or temporary malformed captures;
they do not alter downloaded datasets or analyst alert history.

| Control path | Deterministic check | Result |
|---|---|---|
| Scenario start and incremental work | Start a slow C2 scenario; observe at least one event while status is still `running`, before all 32 events finish | Pass |
| Start while running | Second start and direct event ingest return HTTP 409 | Pass |
| Stop | Task finishes as `stopped`; processed count remains fixed after cancellation | Pass |
| Restart and completion | Fast replay starts after stop, processes all 32 events, reports `complete`, and retains earlier alerts | Pass |
| Speed | API rejects values outside 0.1–10,000; unit check confirms 1.5/2 and 2/2-second event gaps | Pass |
| Public preset absent/malformed | Missing file returns 422; malformed header and truncated packet report `failed` with error | Pass |
| Runtime exception | Source exception reports `failed`; prior and already committed alerts remain; next replay completes with error cleared | Pass |
| Immediate stop | Cancel before scheduled coroutine starts still reports `stopped` and runs cleanup once | Pass |
| Cleanup exception | Source-close failure reports `failed` and still invokes remaining cleanup | Pass |

Two replay-control defects were found and fixed. Previously, a stop before the
scheduled coroutine's first instruction left status at `running` and skipped
source cleanup. The existing task now hands cleanup ownership to the coroutine
when it starts; an immediate stop cleans the pending source itself. A cleanup
exception is reported as replay failure instead of escaping with stale status.
Previously, a public PCAP with a valid header but truncated packet could be
reported as `complete`; public-preset replay now treats that structural truncation
as a failure. Ordinary corrupt packet handling outside this preset path remains
unchanged. SQLite alert history is never reset on stop, failure or restart.

This validates control behavior on local simulated/replayed metadata. It does
not establish detector accuracy or throughput. No alternate replay service,
broker, active network probing or payload decryption was added.

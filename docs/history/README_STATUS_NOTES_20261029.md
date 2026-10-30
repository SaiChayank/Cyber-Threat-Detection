# README status notes, 28 September to 29 October 2026 (historical)

These dated checkpoint notes were the top of the README until 30 October 2026. They describe
their own snapshots, including counts and limits that have since changed. The current state
is in [Current status](../CURRENT_STATUS.md).

**Route change, 29 October 2026:** public-dataset qualification has stopped.
Detector quality is now measured on owner-recorded, labelled lab captures with
the read-only [lab evaluation harness](docs/LAB_EVALUATION.md). No detector, model
or gate change. See [the current sequence](docs/COMPLETION_EXECUTION_20261018.md).

**Monitor recovery, finalized 21 October 2026:** malformed SSE alerts now trigger
durable-history reconciliation, preventing a later valid message from hiding a
missing repaired record. Three frontend regressions, 616 backend tests,
typecheck/production build and a real proxy/SSE/Monitor fault-recovery check pass.
No detector/model/gate change. See [the correction](docs/MONITOR_ALERT_CONTRACT_20261021.md)
and [the current completion sequence](docs/COMPLETION_EXECUTION_20261018.md).

**Current clean-checkout rehearsal, 20 October 2026:** local commit `f380837`
passes isolated installation, 606 base-environment backend tests (three optional
research-tool skip reports), TypeScript, production build, incremental Monitor
replay and restart/resume with 15 unchanged alerts. All seven model hashes match.
Scoped core: 4,256.97 metadata events/sec, processing + SQLite p95 0.8938 ms;
direct loopback API-to-SSE: 100/100, p95 246.11 ms. These exclude capture/browser
throughput. No setup patch was needed; local updates remain unpushed. See
[current reproduction evidence](docs/CLEAN_CHECKOUT_20261020.md) and
[the current execution plan](docs/COMPLETION_EXECUTION_20261018.md).
Required detector-quality gates remain unresolved: **final release NOT READY**.
Earlier dated checkpoints below retain their historical counts and limitations.

**Application hardening, 19 October 2026:** oversized alert cursors are rejected
before SQLite/SSE access, and PCAP staging storage failures return a recoverable
error with cleanup. Latest source run: 557 backend tests pass, TypeScript/build
pass, all nine frozen demo traces unchanged. Loopback delivery: 100/100 records,
p95 244.69 ms. See [cursor fix](docs/API_CURSOR_VALIDATION_20261019.md) and
[upload recovery](docs/UPLOAD_STORAGE_RECOVERY_20261019.md). Required detector
quality remains unresolved; this is not a new clean-checkout or release acceptance.

**Restart follow-up, 18 October 2026:** two production lifetimes preserve all
30 retained alerts, sequence-resumed SSE and Monitor recovery pass, and five
existing restart/resume tests pass. This closes the earlier checkpoint's restart
gap. Detector-quality blockers remain. See [verification](docs/RESTART_COMPLETION_20261018.md)
and [the remaining execution plan](docs/COMPLETION_EXECUTION_20261018.md).

**Current reproduction checkpoint, 18 October 2026:** fresh local commit `4e92b3b`
passes installation, 531 backend tests (three optional research-tool skips),
TypeScript, production build and incremental demo. Installer reports zero npm
vulnerabilities, superseding the older dated advisory status below. Full current
rehearsal is partial: restart was not repeated. Detector-quality blockers remain.
See [the dated checkpoint](docs/CLEAN_CHECKOUT_20261018.md); these local changes
have not been pushed.

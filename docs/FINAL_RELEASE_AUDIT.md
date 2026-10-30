# PS26145 / Univect final release audit

> **Historical (2 October 2026).** This audit's counts and verdict describe that snapshot. The current state, with real-traffic results and all later work, is in [Current status](CURRENT_STATUS.md).

**FINAL SIH RELEASE STATUS: NOT READY**

Audited 2 October 2026 (Asia/Calcutta). Three BLOCKERs remain. The working local
demo is reproducible; this does not satisfy the failed or unassessed detector
quality gates. No feature, detector, model, threshold, promotion gate or dependency
manifest was changed. No training or new reserved evaluation was performed.

## Audited baseline and method

Inspected the governing screenshots as transcribed in [Expected solution](EXPECTED_SOLUTION.md),
the [completion plan](COMPLETION_PLAN.md), all runtime layers, feature/model contracts,
tests, validation protocols, saved reports, provenance manifests and frontend flows.
Dataset-download/research utilities were distinguished from passive runtime ingest.

The input was a private local Git snapshot of the pending working tree, **not a
published release commit**: `38b19c66674b654fb6ae0c1e4a8649408ca62aed`, tree
`b5d5772421d8b4f7e6d930bf2ff9cd2b0845f030`, parent
`186d768dee293d373111ad75c60cb861e9b6b2f5`. It was cloned with
`--no-checkout --no-local --no-hardlinks`, then fetched and checked out directly,
so the new attributes applied before any file checkout. The real branch/index
was not committed or staged. [Audit JSON](verification/release-audit/audit.json)
records the new directory, commands' evidence and source hashes.

The fresh checkout began without `.venv`, `node_modules`, `.env`, raw datasets or
an analyst database. Following README, `npm install` and `npm run dev` installed
dependencies in a new venv with system/user site packages excluded and fresh caches.
Dev API/dashboard startup, `npm run typecheck`, `npm run build`, `npm start`,
the documented demo/preflight/tests/benchmarks all ran. Existing optional Playwright
verification was invoked through `npm exec`; it was not added as an application
dependency. Tests used temporary databases. Owned services were stopped afterward.

PASS means the stated software/workload check passed. PARTIAL means implemented
coverage with an unresolved acceptance or visibility limit. FAIL means the specified
criterion failed. A disabled experiment is not promoted merely because tests pass.

## Final requirement table

| REQUIREMENT | STATUS | EVIDENCE | REMAINING LIMITATION |
| --- | --- | --- | --- |
| No source probe | PASS | `detection/pipeline.py`, `ingest/`, offline socket-prohibition regressions; full suite passes | Software audit, not physical NIC/diode certification. Dataset downloads and analyst loopback calls are separate from observed endpoints. |
| No ingest return-path dependency | PASS | Metadata/PCAP read-only normalization; no endpoint handshake/query in inference | Imported reverse metadata requires explicit observation; raw reverse packets are not joined into invented flow summaries. |
| No inline blocking | PASS | Alert-only Pipeline/API; no firewall/mitigation action path | Replay Stop stops local processing, not production network traffic. |
| No TLS/QUIC payload decryption | PASS | `ingest/protocol_parsers.py`, encrypted visibility tests | Raw TLS ClientHello/JA3 only when complete in one packet; supplied QUIC metadata only. |
| SYN DDoS | PASS — controlled functional gate | [Fresh SYN report](verification/release-audit/syn_flood_validation.json): TP6/TN6/FP0/FN0, precision/recall 100%, FPR 0%; rate/SYN/diversity/incremental gates pass | Small controlled packet/summary matrix; no independent field accuracy claim. |
| UDP DDoS / suspected spoof indicators | PARTIAL — B1 | [UDP](verification/release-audit/udp_flood_development.json) and [spoof](verification/release-audit/spoofed_source_validation.json): both TP4/TN2/FP4/FN0; recall 100%, precision 50%, FPR 66.67% | Benign bulk/distributed clients match. Spoof predicate disabled; generic DDOS remains active. Passive evidence cannot prove forgery/reflection. |
| C2 beaconing | PARTIAL — B1 | [Fresh C2 report](verification/release-audit/c2_beacon_development.json): TP3/TN6/FP2/FN3; recall 50%, precision 60%, FPR 25% | Health checks/telemetry FPs; slow/rotating peers missed by bounded history. |
| DGA | PARTIAL — B2 | Historical active guard recall 7.97%/24.22% on different inspected cohorts; old public candidate recall 76.77%, separate DNS FPR 2.34%; weighted validation recall 92.80%, precision 99.63%, FPR 1.82% | Both candidates disabled. Weighted reserved domain and separate benign-DNS evaluation unavailable; no new public scoring in this audit. |
| DNS tunnelling | PARTIAL — B3 | Disabled causal candidate's prior validation TP5/TN5/FP0/FN0, query 5/12; [formal protocol](DNS_TUNNELLING_FORMAL_VALIDATION.md) | No eligible untouched, labelled full-QNAME/QTYPE real-tool set meeting20  positive/50 benign sessions. Default hybrid exists; rule-only comparison is not full-hybrid accuracy. |
| Encrypted-session indicators | PARTIAL — B1 | [Fresh encrypted report](verification/release-audit/encrypted_session_validation.json): TP3/TN6/FP4/FN5; recall 37.5%, precision 42.86%, FPR 40% | Single lab JA3 shortcut, benign fingerprint overlap and novel/sparse/QUIC misses; experimental. |
| Reconnaissance | PARTIAL — B1 | [Fresh recon report](verification/release-audit/recon_development.json): TP4/TN3/FP3/FN1; recall 80%, precision 57.14%, FPR 50% | Authorized scanner/inventory/discovery FPs; slow scan FN. Fan-out cannot establish authorization. |
| Possible exfiltration | PARTIAL — B1 | [Fresh exfil report](verification/release-audit/exfil_development.json): TP4/TN2/FP4/FN1; recall 80%, precision 50%, FPR 66.67%; byte-accounting stress passes | Backup/upload/sync/replication overlap; no proof of stolen content. Missing reverse stays unavailable. |
| Every enabled detector satisfies its predeclared quality gate | FAIL — B1/B2/B3 | Controlled reruns above and unchanged DGA/tunnel protocols | No new candidate was enabled, but existing baseline heuristics are not release-quality classifiers. Synthetic fit-time scores do not override failed gates. |
| Failed/unassessed candidates disabled | PASS | Fresh Pipeline telemetry: DGA=false, DNS candidate=false; weighted/public research models not default runtime; spoof predicate diagnostic only | Default baseline heuristics remain active with explicitly disclosed failures. |
| False positives and score limits disclosed | PASS | [Model matrix](MODEL_AND_VALIDATION.md), protocols, alert evidence and this table | Posteriors/heuristic scores are not calibrated compromise probabilities. |
| Incremental causal extraction | PASS | `features/extractor.py`, timestamp-order tests, source/peer/query causal regressions | Flow-summary means are proxies, not packet/record sequences. |
| Alerts before scenario completion | PASS — demo scope | [Preflight](verification/release-audit/demo-preflight.json); eight standalone fixtures/ALL; [production ALL20x](verification/release-audit/default-replay.json):256 events/15 alerts/seven classes | API first alert observed at processed 39 while running; all class observations before256. Controlled timing is not independent threat quality. |
| Bounded stream state | PASS with limits | Source4096×512 history, target 512 each TCP/UDP, source-byte61 buckets, global rates11 buckets, bounded cache/session/dedup/error/latency buffers; regressions | Identity overflow is a lower bound; eviction shortens history; SQLite history intentionally grows on disk. |
| Late-event handling | PASS | Watermark rejects late events before state mutation; counter/regressions | Drops rather than reorders late input; bucket overhang is less than one second. |
| SQLite persistence/restart/pagination | PASS |225-test suite includes real API restart, ordering, filtering, duplicate-ID and corrupt/unavailable DB cases | One local DB; duplicate IDs raise an error without replacing history. No migration or external storage. |
| API alert acceptance/contract | PASS | Full tests, fresh health/proxy startup,100 deterministic delivery alerts | Local single-worker service; no production auth/multi-user guarantee. |
| SSE delivery and disconnect/resume | PASS | [Fresh100-alert benchmark](verification/release-audit/api-sse-benchmark.json): durable records/IDs match; resume integration and browser disconnect tests pass | Direct loopback measurement excludes Next.js/rendering; no concurrent-subscriber capacity claim. |
| Replay start/stop/restart/errors/speed | PASS | Full replay-control regressions, production UI checks, ALL20x and offline CLI15 alerts | Existing public presets need optional prepared local datasets. |
| PCAP upload validation/cleanup | PASS | Full upload tests plus browser checks:16MiB limit, malformed/truncated/fake input, unsupported link type, Stop cleanup and next replay | Classic Ethernet PCAP only; no archives, URLs, PCAPNG or TCP reassembly. |
| Monitor/nav/filter/detail/export/errors/reconnect | PASS | [Fresh UI report](verification/release-audit/monitor-ui.json):20/20 checks;1440×1000,768×1024,390×844,320×740;0 unexpected console/runtime errors | Chromium154 viewport simulation, not physical touch/Safari/Firefox. UI/export latest200 loaded alerts; full history remains pageable. |
| Core >=2,000 metadata events/s | PASS | [Fresh core](verification/release-audit/core-benchmark.json):20,000 events,1,170 alerts,3.200962s,**6,248.12/s** | Synthetic metadata core only; excludes capture/API/SSE/browser. |
| Processing+SQLite p95<50 ms | PASS | Same core run: p50 **0.0883 ms**, p95 **0.8070 ms** | One-machine run; benchmark percentile convention recorded, not field capture latency. |
| Loopback API-to-SSE p95<1,000 ms | PASS |100/100 alerts; p50 **149.52 ms**, p95 **247.48 ms**, p99 **259.10 ms** | Excludes capture, Next.js proxy, rendering and concurrent subscribers. Serial batch191.47/s is not sustained capacity. |
| Backend tests | PASS | [Fresh test log](verification/release-audit/backend-tests.log):**225 passed**,0 failed/skipped,53.75s | One existing Starlette/httpx deprecation warning. Tests preserve documented failed quality outcomes. |
| TypeScript | PASS | [Fresh compiler log](verification/release-audit/typecheck.log): `npm run typecheck` | This audited snapshot/environment. |
| Production build/start | PASS | [Fresh build log](verification/release-audit/production-build.log), production Monitor/proxy tests | Python install is bootstrapped by documented dev/manual setup before production start. |
| Clean checkout works | PASS — runtime demo; PARTIAL — all artifacts | Fresh independent Git checkout/venv/caches; README install/build/start/tests/demo/benchmark succeeds | Snapshot not published; three inactive research artifacts have Windows byte-integrity failure H1. |
| Model hashes match | FAIL — H1 for inactive models | [Integrity report](verification/release-audit/clean-model-integrity.json): active main and both DGA artifacts match; original tree6/6 match; clean checkout3/6 match | CRLF conversion breaks `public_cic.json`, `public_dga.json`, `public_tls.json`; LF normalization restores expected hashes. None is activated. |
| Data/protocol hashes and history preserved | PASS — manifested scope | [Raw integrity](verification/release-audit/raw-data-integrity.json):69/69 source entries; frozen DGA plan/protocol and demo preflight match; analyst DB checksum unchanged | Raw data is excluded from Git and not needed for demo. Unmanifested derived/cache files are not certified. |
| Documentation matches implementation/results | PASS with explicit history | Primary docs/report currency, prior documentation audit and this new report distinguish synthetic/public/active/disabled/scopes/failures | Older report bytes/gates preserved as historical. Fresh evidence is saved separately, not relabelled into old measurements. |

## Issues and release decision

| ID | CLASSIFICATION | Remaining issue |
| --- | --- | --- |
| B1 | BLOCKER | Enabled UDP/C2/recon/exfil/encrypted baseline quality fails hard benign controls. Some positives/negatives are identical in available metadata; threshold tuning cannot establish intent. |
| B2 | BLOCKER | DGA quality acceptance unresolved: current guard's weak public recall, failed old candidate, missing weighted reserved-domain/separate-DNS results. |
| B3 | BLOCKER | DNS-tunnelling formal quality/timing acceptance lacks eligible independent real-tool labelled full-snaplen data. Development cases cannot replace that set. |
| H1 | HIGH | Three inactive public-model JSONs lack LF checkout attributes; hashes break on Windows. Preserve stored artifacts/hashes, fix packaging in a separate task with a regression. |
| H2 | HIGH | Pending local changes/audit evidence are not published at the README GitHub URL. Auditing a local snapshot does not make the remote a release. |
| M1 | MEDIUM | DNS/TLS/QUIC visibility and public capture-label/truncation limitations. No active lookup/decryption is an acceptable workaround. |
| M2 | MEDIUM | Local single-worker/auth scope and Chromium-only responsive verification; UI limits its loaded/exported view to200 alerts. |
| M3 | MEDIUM | Approximate bucket windows, eviction and entropy lower bounds are disclosed limits of bounded state. |
| L1 | LOW | Existing TestClient deprecation warning; no test failure. |
| L2 | LOW | Python requirement ranges are not fully locked; [installed versions](verification/release-audit/python-packages.json) record this run, not future resolution certainty. |

No gates were weakened and no failed candidate was promoted. The audit's Definition
of Done **passes** because every requested area has an evidence-backed disposition;
the project release gate **fails** because BLOCKERs remain. No READY declaration,
commit or push was performed.

## Measurements before versus after

The prior saved core run was 5,649.91 events/s/p95 0.8416 ms; this clean-checkout run
is 6,248.12 events/s/p95 0.8070 ms. Prior direct API-to-SSE p95 was 240.27 ms; this run
is 247.48 ms. All performance gates pass. These are separate environment/workload
runs, not an optimization claim. Hardware remains Ryzen 7 8845HS,8 physical/16
logical CPUs,16,356,941,824 bytes visible RAM, Windows 11 build 26300, Python 3.13.5;
full hardware/source/time/percentile records are in the two fresh JSONs.

The earlier clean attempt was 219 passed/4 packaging failures. Corrected snapshot
now passes225 tests, TypeScript/build, production UI and documented replay. The
three inactive-public-artifact failures were outside those existing packaging tests
and remain unfixed. All seven controlled detector count sets are unchanged from
their earlier development reports; this audit freshly binds them to audited source.

## Exact files to commit and push

[release-files.txt](verification/release-audit/release-files.txt) is the exact
repository-relative list of pending modified/new files, including this report and
all new evidence. It covers prior UI/benchmark/demo/setup/documentation work as well
as this audit; those prior implementation changes were preserved, not made anew.
The list is a review/commit manifest, not an instruction to bypass release blockers.

Do **not** commit `.venv`, `node_modules`, `.next`, caches, `.env`, temporary
checkout/log services, raw captures or the analyst SQLite database. Frozen model
and raw-data hashes were not rewritten. Existing numerical reports were not
overwritten in the developer checkout; fresh controlled/performance reports are
under `docs/verification/release-audit/`.

## Exactly next

The smallest next task is **inactive-model packaging integrity only**: preserve
the three public-model JSON bytes/checksums through Windows checkout and add a
checkout regression for all six artifacts. Then address B1/B2/B3 through separately
authorized, frozen-evaluation tasks using genuinely observable signals and eligible
labels. No additional phase starts automatically, and passing the packaging task
will not remove the detector-quality BLOCKERs.

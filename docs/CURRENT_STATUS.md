# Current status (30 October 2026)

Univect (PS26145) is a passive, read-only detector of six threat categories in unidirectional IP
traffic, with a streaming pipeline, a standard alert schema and a dashboard. Everything below was
checked on this date; nothing is marked done that was not run.

## Verification summary

| Check | Result |
| --- | --- |
| Backend tests (`pytest -q`) | 820 passed |
| Frontend tests, TypeScript, production build | 3 passed; typecheck passes; build passes |
| Dependency audit (`npm audit`) | 0 vulnerabilities |
| Frozen demo preflight (`python -m replay.demo_pack`) | passes; nine traces identical |
| Live production run (API + dashboard) | demo replay: 256 events, 15 alerts in 7 classes, p95 0.84 ms; SSE resume from sequence 10; real 8.8 MB PCAP upload processed (10,980 events); garbage upload rejected (HTTP 422) |
| Fresh clone from GitHub (`0a22465`), new venv and `npm ci` | 810 passed, 3 skipped, demo passes, typecheck and build pass, 0 vulnerabilities. The working copy collects 820 tests because it also has the optional `stream-unzip` research package; its 8 dependent tests skip cleanly in a minimal install |

## Requirements (problem statement) and status

| Requirement | Status | Evidence |
| --- | --- | --- |
| Read-only ingest, no probes, no return path, no inline blocking | Implemented | Tests forbid outbound sockets in the pipeline and in the live collector ([Flow export](FLOW_EXPORT_IMPORT.md)) |
| No TLS/QUIC decryption | Implemented; raw QUIC JA4 deliberately omitted | [Encrypted-session detection](ENCRYPTED_SESSION_DETECTION.md) |
| Streaming, bounded latency | Implemented | Alerts mid-replay; core p95 about 1 ms ([Performance](PERFORMANCE_VALIDATION.md)) |
| Stated throughput | Implemented | About 3,300 metadata events/s; full PCAP path about 2,100-3,000 packets/s ([PCAP throughput](PCAP_THROUGHPUT.md)) |
| Standard alert schema | Implemented | Timestamp, flow ID, class, confidence, evidence, severity |
| Inputs: PCAP, PCAPNG, NetFlow v5/v9, IPFIX, sFlow | Implemented (files and a receive-only live collector) | [Flow export](FLOW_EXPORT_IMPORT.md), [PCAPNG](PCAPNG.md) |
| DDoS: SYN, UDP, spoofed-source, slow-HTTP/slow-read | Implemented | Spoofed sources are an evidence field, not a class ([Spoof indicators](SPOOF_INDICATORS.md)) |
| Botnet C2 beaconing | Implemented; **measured on real traffic** | [Real capture results](REAL_CAPTURE_RESULTS.md) |
| DGA domains and DNS tunnelling | Implemented; tunnelling **measured on a real tool capture** | Same |
| Malware in encrypted sessions (JA3/JA3S/JA4, sizes, timing) | Implemented; synthetic validation only | [Encrypted-session detection](ENCRYPTED_SESSION_DETECTION.md) |
| Reconnaissance, data exfiltration | Implemented; synthetic validation only | [Model report](MODEL_REPORT.md) |
| Dashboard: live and replayed alerts, severity, confidence | Implemented | Monitor, filters, detail, export, DDoS sub-type |
| Documentation of models, features, training, validation | Implemented | [Model report](MODEL_REPORT.md) |

## Real-traffic results (the strongest evidence)

- **Botnet C2:** real CTU-13 Neris and benign captures. After tuning on train/validation slices, the
  held-out test slice detected the botnet (1/1; 10 of 11 alerts correct; 0.20 benign false alerts per
  1,000 events), though late.
- **DNS tunnelling:** a real dnscat2 one-hour capture is detected (125 alerts, all correct) with 0
  tunnelling false alerts in 236,845 benign events.
- **False-positive fixes from real data:** four principled guards cut benign false alerts on real DNS
  from 47 to 16 (0.068 per 1,000 events) with detection unchanged.

## Honest limits

- **Unmeasured on real traffic:** DDoS floods, slow-HTTP/slow-read, exfiltration, DGA recall and
  encrypted malware are validated only on controlled synthetic cases. Whatever those cases do not
  cover (for example benign look-alikes such as backups versus exfiltration) can still alert.
- **Weak independence:** the C2 test slices come from one recording of one botnet family; the DNS
  result is one tunnel run, not the frozen protocol's 20 positive and 50 benign sessions.
- **Known remaining false alerts:** DGA on real concatenated-word domains, browsing fan-out as
  reconnaissance, late C2 detection (about 74 of 95 minutes on the test slice).
- **Models:** the classifier is trained on synthetic data; confidence is a heuristic strength or an
  uncalibrated posterior, never a probability. The DGA and DNS-tunnel candidate models stay disabled.
- **Scope:** single-worker local service, no authentication or multi-user support, Ethernet captures
  only (classic PCAP and PCAPNG), single-segment or in-order TLS handshakes, no QUIC JA4.
- **Release status:** the 2 October audit's "NOT READY" verdict rested on detector-quality gates for
  independent real data. Those gates are only partly evidenced (C2 and DNS tunnelling), so this is
  delivered as a **functionally complete, tested prototype**, not as a field-validated classifier.

## Run it

See the [README](../README.md) (`npm install`, `npm run dev`, then http://localhost:3000/monitor), the
[lab capture protocol](LAB_CAPTURE_PROTOCOL.md) to record your own labelled captures, and the
[tuning workflow](TUNING_WORKFLOW.md) to score and tune them.

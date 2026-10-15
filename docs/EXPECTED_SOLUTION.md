# PS26145: requirement traceability and actual delivery

Audited **2 October 2026**. The owner's four screenshots govern this prototype:
one-way passive IP observation, AI/ML classification/scoring, incremental alerts,
evidence/severity/confidence dashboard, throughput evidence and source/model/
training documentation. Required encrypted-session detection was not removed.
The six official categories use seven labels because DGA and tunnelling are separate
modules. Additional website visuals do not replace expected detection coverage.

## Required solution versus implemented evidence

| Requirement | Implementation | Acceptance scope / remaining limit |
| --- | --- | --- |
| Read-only ingest | `TrafficEvent` simulated/exported metadata; incremental classic Ethernet PCAP reader and adapter; offline `replay.cli` | No source probe/handshake/return-path dependency. Loopback analyst API is separate. Native NetFlow/IPFIX/sFlow collectors are not implemented; exporters need metadata normalization. |
| Causal feature extraction and AI/ML inference | Bounded `FeatureExtractor`, portable hash-checked synthetic Gaussian NB, rules and category guards | Current 20-feature model is synthetic-trained; rule/evidence-only corrections are documented. Public/weighted DGA and DNS-tunnel candidates are disabled. |
| Volumetric/protocol DDoS | Target TCP initial-SYN rate/share; target UDP rate/size/diversity/concentration; generic rate path | Controlled SYN functional gate passed at recorded revision. UDP benign high-volume FPs and spoofed-source identifiability remain unresolved; no passive proof of forgery/reflection. |
| Botnet C2 beaconing | Same-peer IAT mean/CV, repeated history, source destination count | Incremental controlled demo works; periodic benign clients overlap and slow/rotating beacons are missed. Quality gate failed. |
| DGA and DNS tunnelling | Active conservative first-label entropy/length/bigrams; long TXT/NULL rule and synthetic model; opt-in causal tunnel candidate | Active DGA recall remains weak. Weighted DGA and tunnel formal evaluations lack reserved data; no promotion. Public truncated captures do not establish tunnel recall. |
| Encrypted-session malicious indicators | Supplied encrypted/TLS/QUIC metadata, single-packet TLS ClientHello JA3 where visible, causal size/timing features | No payload decryption. Single lab-JA3 shortcut, hard benign FPs and low recall; experimental. No raw QUIC handshake fingerprint/JA3S/JA4 extraction. |
| Reconnaissance | Source ten-second host/port fan-out, SYN evidence and source-scoped dedup | Rapid scans alert; authorized scanner/inventory/discovery FPs and slow-scan misses. No graph/correlation subsystem or authorization inference. |
| Possible exfiltration | Bounded source-forward byte totals/rate; observed current-event reverse ratio only when available | Qualified possible-exfiltration wording. Backups/uploads/sync/replication overlap. Cannot prove stolen content, intent or Internet-egress position. |
| Standardized alerts and dashboard | Timestamp, flow ID, class, score, evidence, severity, engine, tuple, UUID; SQLite persistence and sequence-based SSE; Monitor controls/filters/detail/export | Working local interface. Latest 200 displayed alerts; full history is pageable. Scores are uncalibrated. No production authentication or multi-user authorization. |
| Streaming with bounded latency | Event-by-event processing, paced/stoppable replay, persisted-alert SSE resume | Controlled demo's seven threats alert before completion. Core and direct API-to-SSE measurements have distinct scopes; browser rendering latency unmeasured. |
| Stated throughput | Core+SQLite >=2,000 metadata events/s and p95<50 ms; separate loopback API-to-SSE p95<1,000 ms | Latest 1 Oct runs:5,649.91 events/s, core p95 0.8416 ms; delivery p95 240.27 ms,100/100 records. These are project gates, not numbers specified by the screenshots. |
| Reproducible source/demo/docs | README, requirements/lockfile, bundled model, hashed demo fixtures and validation reports | Corrected fresh runtime/demo passes 225 tests, TypeScript/build and 20/20 production Monitor checks. Three inactive public artifacts fail Windows byte integrity. Local updates are not all published. See final release audit. |

The project delivers a working passive **prototype**. It is not accepted as an
independently validated real-world threat classifier merely because API, replay,
persistence, dashboard and performance gates work. Per-threat sources, exact rules,
counts, false-positive patterns and activation decisions are in
[Model and validation](MODEL_AND_VALIDATION.md). Report revisions are explicit in
[Streaming validation](STREAMING_VALIDATION.md).

## Architectural constraints

Input files are read-only; detections never contact monitored endpoints, complete
handshakes, block traffic or decrypt application payload. Offline socket-prohibition
tests cover the software path, not physical diode/NIC isolation certification.
The analyst services bind to loopback; they are not an ingest return channel.

Classic Ethernet PCAP is supported. PCAPNG, other link types, fragmented TLS/DNS TCP
reassembly and IPv6 extension-header decoding are unsupported. DNS accepts complete
UDP53 or the first complete length-prefixed TCP53 message in a packet, with bounded
compression decoding. DoH/DoT conceal names; LLMNR5355 is not classified as ordinary
DNS. Capture truncation cannot be repaired by lowering detector thresholds.

Missing reverse traffic remains unavailable. Explicitly observed zero reverse
bytes means availability is true but a finite ratio is undefined. Raw reverse
packets are not automatically joined into cumulative directional summaries.
Encrypted flags/port inference and fingerprints are metadata indicators, not
decrypted malware evidence. Forward volume alone cannot establish business intent.

## Verification provenance

The latest source-matching benchmarks and their exact exclusions are in
[Performance validation](PERFORMANCE_VALIDATION.md). Historical synthetic/public
metrics are preserved with original hashes; none was relabelled as a new final test.
The [demo guide](FINAL_DEMO.md) supplies eight scenarios and offline fallbacks.
The [completion plan](COMPLETION_PLAN.md) separates delivered structure from
unresolved quality, clean-checkout retesting and publication.

The subsequent [final release audit](FINAL_RELEASE_AUDIT.md) completed the corrected
clean runtime/demo check, refreshed controlled/performance evidence in separate
reports, and found three detector-quality BLOCKERs. **Release status: NOT READY.**
It also records the inactive-artifact packaging and publication issues.

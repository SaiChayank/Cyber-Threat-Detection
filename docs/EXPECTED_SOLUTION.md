# PS26145 — governing requirements and delivered prototype

The four screenshots supplied by the project owner are the governing requirements.
They supersede conflicting suggestions in earlier planning documents. In particular,
encrypted-session malware remains required; it has not been removed from this build.
Optional features must not replace the expected solution.

## Required behavior and implementation

1. **Read-only traffic ingest.** `ingest/pcap_reader.py` incrementally reads classic
   Ethernet PCAP; `ingest/metadata.py` adapts observed records. `schemas/traffic_event.py`
   accepts validated simulated or exported metadata. `replay/cli.py` provides entirely
   offline input-to-alert processing. No detector contacts the source or destination.
2. **Feature extraction.** `features/extractor.py` computes 20 causal numeric inputs:
   traffic rates, source entropy, SYN fraction, inter-arrival mean/CV, host/port fan-out,
   domain entropy/length/digits/bigram statistics, DNS record type, encrypted flag,
   packet-size variability, outbound volume, observed byte ratio and its availability,
   a lab fingerprint indicator, and history count. State is bounded and late events
   are dropped and counted. The training process imports this same implementation.
3. **Model inference.** `ml/model.py` loads a fitted Gaussian naive Bayes classifier
   from a portable, hash-verified JSON artifact. `ml/train.py` reproduces training and
   validation. `detection/pipeline.py` combines its output with an independent rule
   baseline and emits alerts before a scenario ends.
4. **All required threats.** DDoS, C2 beaconing, DGA, DNS tunnelling, encrypted-session
   malware suspicion, reconnaissance, and exfiltration are present. The official DGA /
   tunnelling category is implemented as two modules. Model labels can produce more
   than one alert through the accompanying rules; classes need not be exclusive.
5. **Standardized alert output.** `schemas/alert.py` provides timestamp, flow ID,
   threat class, confidence score, and supporting evidence, plus severity, connection
   endpoints, engine, and numeric evidence. `persistence/store.py` records alerts in
   SQLite. `/api/stream` delivers them through SSE while processing continues.
6. **Simple dashboard.** `frontend/src/main.ts` displays replayed detections with
   severity and confidence, and provides class filters, evidence inspection, replay
   controls, PCAP upload, telemetry, and JSON export. The local API can serve the
   production build on the same port. Additional tools do not replace core coverage.
7. **Streaming and bounded latency.** Each event updates state and runs inference
   immediately. Alerts do not wait for end-of-run aggregation. Event-time replay is
   paced and stoppable. State and query response sizes are bounded. The browser shows
   the most recent 200 alerts; retained alert history is queryable through the API.
8. **Defined and demonstrated throughput.** The team target is 2,000 simulated
   flow-metadata events/sec and processing+persistence p95 below 50 ms. Run
   `python -m benchmarks.run --events 20000`. `benchmarks/latest.json` contains actual
   timings, host information, sample size, and pass/fail fields. This is a core plus
   SQLite benchmark, not a capture-to-browser throughput claim.
9. **Model/features/training documentation.** See `MODEL_AND_VALIDATION.md`, the
   generated `ml/evaluation.json`, and the reproducible commands in the README.

## Constraints and honest limits

- Passive observation means the monitoring input has no dependency on sending
  probes, completing handshakes, decrypting traffic, or blocking monitored traffic.
  The local dashboard API is an analyst service in the monitoring enclave, not a
  connection back to the monitored source. Bind it to loopback.
- A unit test prohibits sockets in the inference pipeline. This proves the tested
  software path does not initiate network IO; it does not certify a physical data
  diode, kernel-level NIC isolation, or a production network deployment.
- Encrypted-session detection operates on metadata and size/timing patterns.
  The included fingerprint is an explicitly synthetic lab signature. This is a
  functioning detection module, not a verified real-malware intelligence feed.
- Raw PCAP parsing extracts complete, single-record TLS ClientHello JA3 metadata.
  QUIC events use packet dynamics and externally supplied metadata when present.
  QUIC Initial handshake fingerprint extraction, fragmented TCP reassembly, PCAPNG,
  and IPv6 extension-header decoding are not implemented. Unsupported capture
  formats are rejected; incomplete/unsupported packets may be dropped.
- If a one-way feed does not contain reverse traffic, outbound:inbound ratio is
  **unavailable**, not an invented zero or a meaningful measurement. Exfiltration
  can still trigger a volume-only suspicion with this limitation in the evidence.
  Explicitly observed reverse metadata in exported records enables the ratio.
- DNS encrypted by DoH/DoT cannot yield domain lexical features without a separate
  passively observed plaintext DNS source. Fingerprints alone never prove malware.
- The model is trained on synthetic metadata, with disjoint experiment seeds.
  The same generator family creates all splits; real-world generalization, attack
  family holdouts, deployment FPR and calibration remain unverified.
- Baseline rules may also flag legitimate periodic clients, backups, high-rate
  traffic, or unusual benign domains. Thresholds require deployment-specific tuning.
- The local prototype does not implement production authentication, multi-user
  authorization, source-network capture hardware, or mitigations.

## Verification

`tests/test_pipeline.py` covers every required threat, alert generation before
completion, benign demo behavior, unknown reverse traffic, bounded and causal state,
artifact integrity, persistence across restart, API replay/validation and passive
inference. Existing schema/parser tests are retained. Dashboard replay, responsive
layout, live alerts and evidence inspection were also checked in the browser.

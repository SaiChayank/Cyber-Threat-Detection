# PS26145 — Real-Time Runtime Pipeline Design
**Scope:** The streaming pipeline mechanics only — event flow, concurrency model, state/window management, buffering, ordering, backpressure, failure handling, and messaging-technology choice. No dashboard, API, or storage-backend design happens here.

Target flow (as specified): `Traffic/Replay → Passive Ingest → Parser → Normalizer → Streaming State → Feature Extraction → Detection → Confidence/Severity → Evidence → Alert Output`

---

## 1. Event Flow Overview

| Stage | Consumes | Produces | Sync or Async |
|---|---|---|---|
| Passive Ingest | Raw packets off the mirror NIC (live) or a pcap/flow archive (replay) | Raw packet/flow byte blobs, timestamped on arrival | **Asynchronous** — capture must never block on anything downstream; it only ever writes into a bounded queue (§4) and returns immediately |
| Parser | Raw byte blobs | Structured, format-specific records (PCAP packet, NetFlow/IPFIX/sFlow record) | Asynchronous, pulled from the ingest queue by a worker pool |
| Normalizer | Format-specific records | Canonical `FlowRecord` / `DNSRecord` / `TLSQUICMetadata` (per the approved data model) | Asynchronous |
| Streaming State | Canonical records | Updated keyed state (sketches, Welford accumulators, EWMA, bitmaps, bloom filters — per the approved feature-engineering primitives) | **This stage is where synchronization matters most** — see §3 |
| Feature Extraction | Current record + its relevant keyed state | A feature vector for the record's detector(s) | Synchronous with respect to Streaming State (must read the just-updated state), but the extraction computation itself is fast/non-blocking |
| Detection | Feature vector | Rule verdict and/or classifier score, per detector | Asynchronous — detectors run independently and don't block each other (§10) |
| Confidence/Severity | Raw rule verdict / raw classifier score | Calibrated confidence (per the approved calibration methodology) + a severity level | Synchronous, cheap (a lookup/calibration-curve application) |
| Evidence | Detection result + the feature values that drove it | The alert's `supporting_evidence` payload | Synchronous, cheap |
| Alert Output | Complete alert record | Emitted structured alert (timestamp, flow ID, threat class, confidence, evidence — per the official schema) | Asynchronous — writing/publishing an alert must not block the pipeline from processing the next event |

**General principle:** every stage boundary is a queue, not a direct function call, so that a slow stage backs up into its own queue rather than stalling the stage behind it. This is what makes backpressure (§6) and per-stage failure isolation (§10) possible at all.

---

## 2. Synchronous vs. Asynchronous Operations

- **Never synchronous:** anything touching the network (Passive Ingest reading the mirror interface) or anything touching external I/O (Alert Output publishing/writing). These are always asynchronous, queue-fed operations — a slow downstream consumer (e.g., a dashboard temporarily unavailable) must never propagate backpressure all the way up to packet capture, since capture is the one stage where "just wait" is not a safe option (dropped packets there are lost forever, per the passive/read-only constraint — there is no way to ask for a retransmission).
- **Synchronous within a processing worker:** the Feature Extraction → Detection → Confidence/Severity → Evidence chain, for a *single* event, is a synchronous in-process sequence once that event has been pulled off its queue — there's no benefit to making these four steps independently async from each other for one event, since they're fast, CPU-bound, and inherently sequential (you can't compute confidence before detection runs).
- **Parallel across events, sequential within one event's processing:** many worker instances of the above synchronous chain run concurrently across different events (different flows/keys), which is where the actual throughput comes from — not from making one event's own processing chain asynchronous internally.

---

## 3. Window / State Management

This stage directly hosts the streaming primitives already defined in the feature-engineering task (HyperLogLog, Count-Min Sketch, Welford accumulators, EWMA, bitmaps, Bloom filters), keyed as that task specified (per-destination, per-source, per-(src,dst)-pair, per-domain, per-JA3).

- **State is sharded by key**, not global — a per-destination DDoS counter and a per-(src,dst) C2 accumulator are entirely independent pieces of state, updated independently, which is what allows different events to be processed concurrently without contention on a single shared structure.
- **Short-window state** (DDoS, reconnaissance — seconds to minutes) lives in fast, in-memory structures with tumbling/sliding eviction, exactly as designed in the feature-engineering task.
- **Long-window state** (C2 beaconing, exfiltration baselining — hours to days) is the sufficient-statistics representation already designed (running mean/variance/EWMA, not raw event history), so this stage's memory footprint per key stays constant regardless of horizon length.
- **Read-then-update ordering:** Feature Extraction must read state *after* Streaming State has applied the current event's update, so the feature vector for "this event" correctly reflects "this event's" contribution (e.g., a DDoS rate counter includes the packet that just arrived) — this ordering constraint is why Feature Extraction is described as synchronous-with-respect-to-Streaming-State in §1, even though the two can be separate code modules.
- **Watermark-driven finalization:** a window's aggregate value is not considered final until its watermark (§5) passes, consistent with the causality and allowed-lateness design already approved in the feature-engineering task — this stage doesn't re-derive that policy, it implements it.

---

## 4. Buffering

Every stage boundary has a **bounded** queue (never unbounded — an unbounded queue just converts a backpressure problem into a memory-exhaustion problem later). Three buffering points matter most:

1. **Ingest buffer** (Passive Ingest → Parser): must absorb short bursts (e.g., a DDoS flood's sudden packet-rate spike) without ingest itself blocking. Sized generously relative to expected burst duration, since this is the one buffer where "just make it bigger" is the right first response to overflow, given ingest's own no-blocking requirement.
2. **Detection-dispatch buffer** (Feature Extraction → Detection): holds feature vectors awaiting whichever detector(s) apply to that record's threat-relevant fields (a DNS record only needs the DGA/tunnelling detectors, not the TLS-fingerprint detector) — sized to smooth out the fact that different detectors have different per-event compute cost.
3. **Alert-output buffer** (Evidence → Alert Output): decouples alert generation from however alerts are actually published/stored downstream (a concern for the not-yet-designed backend), so a slow or momentarily unavailable downstream sink doesn't stall detection.

---

## 5. Ordering

- **No global total ordering is required or attempted** — only *per-key* ordering matters (e.g., events for the same destination in DDoS detection, or the same src-dst pair in C2 detection need to be applied to their shared state in timestamp order relative to each other; events for unrelated keys can be processed in any relative order without affecting correctness).
- **Watermarking with bounded allowed lateness**, exactly as specified in the feature-engineering task's §9.4, governs when a window is considered closed. A small per-window grace period admits slightly late arrivals (capture jitter, multiple mirror points with clock skew); anything later than that is handled as a late-dropped event (§9), not retroactively applied.
- **Per-key ordering is enforced by routing**, not by a global sequencer: events are hashed/routed to the same processing lane/worker based on their relevant key (destination IP for DDoS, src-dst pair for C2, etc.), so that a given key's events are naturally processed in arrival order by a single worker without needing a distributed ordering protocol.

---

## 6. Backpressure

- **Backpressure signal propagates backward, never forward as data loss by default.** If Detection is falling behind (e.g., an expensive optional-advanced model is slow), its input queue (the detection-dispatch buffer) fills up; this in turn signals Feature Extraction to slow its production rate (a standard bounded-queue-with-blocking-producer pattern), which in turn slows consumption from Streaming State, and so on back toward Parser.
- **The one place backpressure cannot propagate all the way back to** is Passive Ingest itself, per §2 — capture cannot be told to "slow down" a real network link. Instead, once the ingest buffer (§4, point 1) is full, the system must make an explicit, logged **load-shedding** decision (§7) rather than let backpressure silently stall capture.
- **Per-detector backpressure isolation:** if one specific detector (e.g., an optional-advanced temporal model) is the slow one, only its own dispatch lane backs up — this is why detection is described as running detectors independently in §1, so a slow/failing detector doesn't stall the fast rule-based detectors for other threats.

---

## 7. Queue Limits

- Every bounded queue has an explicit maximum size, chosen relative to the target throughput and acceptable buffering latency (a concrete number is a runtime-tuning decision made once real throughput benchmarking happens, not fixed arbitrarily here).
- **Overflow policy differs by stage, deliberately:**
  - **Ingest buffer overflow:** drop-oldest is preferred over drop-newest — under a genuine flood (which is itself one of the things being detected), the newest packets are the ones most relevant to catching the flood in progress; dropping the oldest buffered packets loses less detection value than dropping the incoming flood traffic itself.
  - **Detection-dispatch buffer overflow:** drop-newest with logging, since by this point the record has already been feature-extracted and a drop here means a missed detection opportunity for that specific event — this should be rare (indicates a genuinely overloaded detector) and always logged as a monitoring signal, not silently absorbed.
  - **Alert-output buffer overflow:** never drop — alerts are the system's entire purpose; instead, this buffer's overflow condition should trigger backpressure into Detection/Confidence-Severity (slowing alert generation) rather than losing an already-computed alert.

---

## 8. Malformed Events

- **Validation happens at the Parser stage**, immediately after raw bytes are read — this is the earliest point structure can actually be checked (Passive Ingest doesn't parse anything, just captures bytes).
- A record that fails to parse (truncated packet, corrupt flow-export record, unexpected format version) is **routed to a quarantine/dead-letter path**, not silently dropped and not allowed to crash the Parser worker — the dead-letter path logs the raw bytes plus the parse failure reason, both for later debugging and because a burst of malformed records could itself be a signal worth surfacing (e.g., a misconfigured exporter, or in principle an attempt to evade parsing).
- Malformed events never reach Streaming State — a bad record must not be allowed to corrupt shared keyed state (e.g., an out-of-range timestamp poisoning a Welford accumulator).

---

## 9. Dropped Events

Three distinct drop scenarios exist, and each is handled differently, deliberately not conflated into one generic "drop" concept:

1. **Capture-level drops** (packets lost at the mirror/tap before or during ingest, e.g., under extreme load) — these are invisible to the pipeline itself (the data never arrived), so the only mitigation is the completeness flag already designed in the feature-engineering task (§9.2 of that document): downstream windows are marked as computed-over-possibly-incomplete-data when gap indicators (sequence numbers, expected-flow-count heuristics) suggest a drop occurred.
2. **Explicit overflow drops** (queue-limit drops per §7) — always logged with which stage, which policy fired, and a timestamp, feeding an operational health metric (not silently absorbed).
3. **Late-arrival drops** (events arriving after their window's watermark grace period has closed, per §5) — logged as late-dropped, explicitly not used to retroactively mutate an already-finalized window or already-emitted alert, consistent with the causality discipline already established.

All three are logged distinctly so a post-hoc review (or a judge asking "how much data did you actually lose and why") can be answered precisely rather than with one undifferentiated drop counter.

---

## 10. Retries and Detector Failure

- **Retries apply only to idempotent, replayable operations** — primarily Alert Output's downstream publish/write step (if writing an alert to storage or a message bus momentarily fails, retry with backoff is safe and appropriate, since re-emitting the same already-computed alert is harmless if deduplicated on the consumer side).
- **Retries do NOT apply to capture-level drops** — consistent with the read-only/passive constraint, there is no way to ask the traffic source (or a data diode) to resend a packet that was never captured; this is a hard limit of the architecture, not a gap to engineer around.
- **Detector failure isolation:** each detector (rule or ML) runs in its own execution context such that an exception in one detector (e.g., a malformed feature vector causing a model to throw) is caught, logged, and **does not crash the pipeline or block other detectors** from processing the same event. A failed detector simply contributes no verdict for that event, and a per-detector health/error-rate metric is maintained so sustained detector failure is visible as an operational signal (e.g., "the encrypted-malware model has been failing on 40% of inputs for the last minute" is something the system should be able to surface) rather than silently degrading detection coverage.
- **Circuit-breaking (design intent, not fully specified here):** a detector experiencing a sustained failure rate above some threshold should be temporarily bypassed (with logging) rather than continuing to consume dispatch-queue capacity for a detector that isn't succeeding — the exact threshold/recovery logic is a tuning decision for implementation, not resolved in this design document.

---

## 11. Technology Comparison

| Option | Throughput | Persistence/Durability | Ordering/Consumer-group support | Backpressure handling | Operational complexity | Python/ML ecosystem fit | Hackathon setup time |
|---|---|---|---|---|---|---|---|
| **Python `asyncio`** (in-process queues, no external broker) | Good for a single-process prototype; bounded by one Python process (GIL-limited for CPU-bound work, though feature/detection code can offload to worker processes if needed) | None — in-memory only, lost on crash/restart | Trivial — a single process controls ordering directly via how it dispatches work | Native (`asyncio.Queue` has built-in bounded-size blocking behavior) | **Lowest** — no external service to install, configure, or operate | **Best** — zero friction with the same Python codebase doing feature extraction and model inference | **Fastest** — nothing to install beyond the standard library |
| **ZeroMQ** | High, low-latency messaging primitive | None built-in — no persistence, no replay, no consumer groups (must be built manually) | Manual — ZeroMQ gives messaging patterns (pub-sub, push-pull) but no ordering/replay guarantees itself | Manual — must implement your own flow-control/backpressure logic on top | Moderate — a library, not a service, but still requires designing the messaging pattern and handling reconnects/acks yourself | Good Python bindings (`pyzmq`), but more low-level plumbing than a broker gives for free | Fast to install, slower to get right (more manual design work for the guarantees this pipeline needs) |
| **Redis Streams** | Good — sufficient for prototype-to-moderate production throughput | **Yes** — persisted log, replayable, survives consumer restarts | **Yes** — native consumer groups, per-consumer-group ordering and at-least-once delivery tracking | Built-in via consumer-group pending-entries and `XLEN`-based backlog visibility | **Low** — a single `redis-server` process, trivial to run locally, no cluster/ZooKeeper/broker cluster needed | Excellent Python client support; Redis is also a natural fit for the keyed-state store in §3 if an external (rather than in-process) state store is later desired | Fast — one process to start, minimal configuration |
| **NATS** (with JetStream for persistence) | High throughput, low latency | Yes, with JetStream enabled (adds configuration) | Yes, via JetStream consumer groups | Built-in flow control | Moderate — a capable, purpose-built messaging system, but a genuinely new piece of infrastructure for the team to learn and operate under time pressure | Decent Python client, less commonly used in the Python/ML ecosystem than Redis | Moderate — more setup and unfamiliar operational surface than Redis for a team that likely already knows Redis |
| **Kafka** | Highest sustained throughput, built for large-scale production log streaming | Yes, strong durability guarantees, the most production-proven option here | Yes, the most mature partition/consumer-group model | Robust, well-understood backpressure/consumer-lag tooling | **Highest** — typically needs ZooKeeper/KRaft, multiple broker processes, and meaningfully more operational knowledge to run correctly | Good Python clients exist, but Kafka's operational weight is disproportionate to a hackathon prototype's actual throughput needs | **Slowest** — real setup and tuning burden, the most likely option to eat hackathon time without a corresponding benefit at this scale |

---

## 12. Recommendation: Simplest Technology That Satisfies the Prototype

**Recommended: Python `asyncio` as the core in-process pipeline engine, with Redis Streams as the single external component — used specifically as the durable buffer between Passive Ingest and the rest of the pipeline, and optionally as the alert-output publish target.**

**Reasoning:**
- The core Parser → Normalizer → Streaming State → Feature Extraction → Detection → Confidence/Severity → Evidence chain is CPU-bound, in-process, and doesn't need cross-process messaging guarantees to function correctly — `asyncio`'s native bounded queues already satisfy the buffering (§4) and backpressure (§6) requirements for this part of the pipeline with zero additional infrastructure, which matters directly for hackathon feasibility.
- The one place a plain in-process queue is genuinely insufficient is **Passive Ingest**, where a crash or restart of the processing side should not mean silently losing whatever was captured but not yet processed — this is exactly what Redis Streams' persistence buys, without the operational weight of Kafka or the unfamiliar-infrastructure cost of NATS. A single `redis-server` process is realistically achievable within hackathon setup time, unlike a Kafka broker cluster.
- **Kafka and NATS are both rejected specifically for being disproportionate to this prototype's actual scale** — their strengths (massive sustained throughput, multi-broker durability, mature partition rebalancing) address problems this prototype does not yet have, and the setup/operational time they cost is exactly the kind of scope-inflation the project's earlier "prioritize a working prototype over unnecessary complexity" guidance warned against.
- **ZeroMQ is rejected** because it would require manually building the persistence, consumer-group, and backpressure-visibility features that Redis Streams provides natively — more design and implementation work for a weaker end result at this scale.
- This combination is also **the most naturally extensible path**: if the prototype later needs to scale beyond one process, Redis Streams' consumer-group model already supports multiple consumers reading the same ingest stream, and the in-process `asyncio` stages can be lifted into separate worker processes communicating via additional Redis Streams without a full architecture rewrite.

---

## 13. LIVE/SIMULATED MODE

- **Traffic source:** Passive Ingest reads directly from the lab's mirror/tap NIC (per the approved lab architecture) in real time — packets arrive as they're generated by the benign generators and attack simulator, exactly as they would from a real unidirectional data-diode feed.
- **Pacing:** entirely determined by the actual generators — there is no artificial pacing control; the pipeline must keep up with whatever rate the lab's traffic generation produces, which is precisely what the PS's throughput-demonstration requirement is meant to exercise.
- **Use case:** this is the mode used to demonstrate near-real-time detection and to measure genuine end-to-end latency (time from packet arrival to alert emission) under realistic, live-generated conditions — the actual target operating mode the PS describes.
- **State behavior:** Streaming State's windows and long-horizon accumulators run continuously, exactly as designed in §3, with no resets except at intentional experiment boundaries (aligning with the lab's `experiment_id` structure, so live-mode state can still be interpreted per-experiment if needed for evaluation).

## 14. REPLAY MODE

- **Traffic source:** Passive Ingest reads from the lab's archived PCAP/flow storage (the `raw_pcap`/`flows` structure from the lab-architecture task) instead of a live NIC.
- **Pacing options, both needed for different purposes:**
  - **Real-time-paced replay** — records are emitted from the archive preserving their original inter-arrival timing, so the pipeline experiences the same temporal pattern it would have live. This is the correct mode for validating that alert timing/latency claims made from a live demo are reproducible and not an artifact of a particular live run.
  - **Accelerated replay** — records are emitted as fast as the pipeline can consume them, ignoring original timing. This is the correct mode for **throughput benchmarking** (directly serving the PS's mandated "state and demonstrate throughput" requirement) and for fast iteration during development/evaluation, where waiting out real elapsed time for every test run would be wasteful.
- **Use case beyond demoing:** replay mode is also how the model-development methodology's train/validation/test evaluation should actually be executed — feeding labeled archived experiments through the **same runtime pipeline code** (same Parser/Normalizer/Streaming State/Feature Extraction implementation used live) rather than a separate offline analysis script. Doing so directly addresses part of the train/serve consistency gap flagged in the prior readiness review: if the identical streaming feature-computation code path is used both to generate evaluation features from replayed archives and to compute features live, that specific inconsistency risk is closed by construction for the runtime side of the pipeline. (This does not by itself resolve the readiness review's full concern — the *original training-data generation* via the offline batch flow-extraction tool at the lab-architecture stage is a separate step this document doesn't redesign — but replay mode is the mechanism by which the runtime and evaluation paths, at least, can be made to share one implementation.)
- **State behavior:** each replay run is scoped to the `experiment_id`(s) being replayed, with Streaming State reset at the start of a replay run (rather than carrying over state from a previous, unrelated replay) unless a test scenario deliberately wants to replay multiple experiments back-to-back to exercise long-horizon state (e.g., testing C2 beaconing detection across a multi-experiment sequence) — a deliberate choice made per test, not a default.
- **Determinism:** because replay reads from a fixed archive rather than a live, non-reproducible network, replay-mode runs are fully repeatable — the same archive, same pacing mode, same pipeline code should produce the same alerts every time, which is valuable both for debugging and for demonstrating consistent behavior to evaluators.

---

**No dashboard, API, or alert-storage backend has been designed in this document** — Alert Output is defined here only as the pipeline's final stage boundary (an emitted, structured alert), with what happens to that alert afterward deferred to a later, explicit task.

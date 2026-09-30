# SYN-flood validation — frozen controlled gate

The following gate was recorded on 30 September 2026 **before generating or
scoring the new controlled evaluation replays**. Existing code, tests, the
historical synthetic `DDOS` replay and streaming reliability report were
inspected first. The frozen deployed model artifact is not retrained or edited.
Only TCP SYN-flood behavior is in scope; non-TCP DDoS behavior is not evaluated
or retuned here.

## Unit, fixtures and gate

The unit is a separately labelled, isolated replay scenario. A positive is a
known SYN flood toward one target; a negative is known benign TCP traffic.
Run each with a fresh production pipeline in timestamp order, without future
events or source queries. A scenario is TP if a `DDOS` alert occurs before its
last event, FN otherwise; a benign scenario with any `DDOS` alert is FP,
otherwise TN. Record the first-alert event position, timestamp and evidence.

The reserved controlled matrix consists of six positive scenarios: three
packet-level SYN floods (single source, 32 balanced sources, and a flood mixed
with unrelated benign TCP to test target isolation) and three homogeneous
aggregated-flow SYN simulations (single source, 32 balanced sources, and the
existing `replay.scenarios.scenario('DDOS')` simulation). It also consists of
six benign scenarios: packet-level high-rate ACK, high-rate PSH/ACK, high-rate
mostly established TCP with a small SYN share, high-rate traffic to a different
destination alongside low-rate SYNs, aggregated high-rate established TCP, and
ordinary low-rate TCP handshakes. The generated packet-level cases use at least
12,000 observed packets over about six seconds so they cross the existing
1,000 packets/sec, ten-second rate floor. The deterministic construction and
source hashes must be recorded with the result. The pre-existing synthetic
`DDOS` replay is reported separately if its `syn` bit lacks an exact packet
count; it cannot be used to claim a packet-exact SYN fraction.

**Acceptance:** TP=6, FN=0, FP=0, TN=6 on the controlled matrix (recall and
precision 100%, benign-scenario FPR 0%). Every positive first alert must
appear before scenario completion and no later than the event that makes
target traffic reach 10,000 observed packets in the current ten-second window.
Packet-level rates must equal uncapped bucket packet totals divided by ten;
packet-level SYN fraction must equal SYN-only packets / target TCP packets.
The SYN-specific decision under test requires target TCP rate >=1,000
packets/second and target SYN fraction >=0.70; this threshold is fixed before
the reserved controlled replay and is not adjusted to its outcomes.
Source entropy must equal zero for one source and approximately five bits for
32 equally contributing sources, with any identity overflow explicitly marked
partial. A benign high-rate TCP scenario must never be marked as SYN flood
solely because it exceeds the rate threshold. Alert evidence must include
rate, SYN fraction, source diversity/entropy, window resolution and whether
the SYN fraction is exact packet observation or a summary proxy.

These are **controlled synthetic functional gates**, not estimates of field
accuracy. A flow summary with only a cumulative SYN flag does not reveal how
many constituent packets were SYN; its fraction is a proxy, and the exact
packet-level fraction gate applies only to packet-level replay. No public
dataset or final holdout is silently assigned scenario-level ground truth.

## Results and decision

The initial run is preserved at `ml/syn_flood_validation_initial.json`. It
reported 6 TP / 6 TN / 0 FP / 0 FN, but review immediately afterward found
that a **cumulative SYN flag on an aggregated flow was being multiplied by its
entire packet count**. A legitimate 4,000-packet flow with one SYN could
therefore look like 4,000 SYN packets. The initial gate pass was insufficient
to accept the implementation; no threshold was changed.

The SYN-specific correction adds an optional `syn_packets` count to metadata.
Raw packet adaptation supplies **one** only for an initial SYN (SYN without
ACK), and zero for SYN+ACK or other packets. A producer of an aggregate may
declare an exact count; without one, the target SYN fraction is unavailable
and cannot trigger the SYN-specific rule. The existing controlled `DDOS`
generator now explicitly declares homogeneous simulated summary counts.
Global model features and the frozen model artifact remain unchanged. TCP
SYN-flood decisions require destination TCP packet rate >=1,000/sec and a
known target SYN share >=0.70. Model-only TCP `DDOS` predictions cannot bypass
this rule. Non-TCP DDoS logic was not changed.

The corrected implementation was replayed against the **same** frozen
controlled matrix as a regression, not misrepresented as a fresh independent
holdout. Machine-readable per-scenario labels, alert evidence, timestamps and
source hashes are in `ml/syn_flood_validation.json`.

| Controlled outcome | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initial, semantically flawed summary count | 6 | 6 | 0 | 0 | 100% | 100% | 100% | 0% |
| Corrected replay of the same cases | 6 | 6 | 0 | 0 | 100% | 100% | 100% | 0% |

First alerts occurred at packet/event 10,000/12,000 (single-source raw),
10,000/12,000 (32-source raw), 11,666/14,000 (raw SYN mixed with unrelated
target traffic), 3/4 (single-source aggregate), 25/32 (32-source aggregate)
and 3/32 (existing aggregate simulation). All occurred when or before the
target first reached 10,000 packets and before completion. The raw first-alert
evidence reported 1,000 target packets/sec and SYN fraction 1.0. Single-source
entropy was 0; the 32-source raw first-alert entropy was approximately 5 bits
and final entropy exactly 5 bits. The final 12,000-packet rate was 1,200/sec,
unaffected by the 512-record per-source history bound. One-second bucket
resolution and entropy truncation status remain in alert evidence. A separate
regression confirms that three sources with a two-identity cap keep full
packet totals while setting `source_entropy_partial=true`.

All six controlled benign scenarios emitted no DDoS alert, including raw
12,000-packet ACK, PSH/ACK and 5%-SYN streams; 14,000 packets with only
2,000 low-rate SYNs toward the target; high-rate established-flow summaries;
and ordinary low-rate handshakes. A further regression tests high-rate
aggregates with a cumulative SYN flag but only 1% declared SYN packets, and
aggregates with no count: neither triggers a SYN flood.

The refreshed 20,000-event mixed synthetic **core + SQLite** benchmark in
`benchmarks/latest.json` measured 4,822 metadata events/sec and p95 0.874 ms,
above the existing 2,000 events/sec and below the 50 ms targets. This is one
unpaced local run, not a speed comparison; it excludes capture parsing, HTTP,
SSE and browser rendering. It does not measure sustained raw SYN PCAP ingest.

**Decision: accept controlled SYN-flood functional behavior for the prototype.**
This is not an independent field-quality claim. The same matrix was replayed
after a semantic defect was fixed, and all labels/traffic are controlled
simulations. A real high-SYN connection surge could still resemble a flood.
Aggregates without a SYN packet count intentionally cannot enter this
SYN-specific rule; old `data/lab/ddos.jsonl` summaries predate the count field
and were left untouched. Source identities are bounded; entropy becomes a
disclosed lower bound on overflow. A fresh, independently labelled full-snaplen
SYN/benign capture is the next evidence needed before claiming transfer beyond
these scenarios. No active probes, return-path assumption or mitigation was
introduced.

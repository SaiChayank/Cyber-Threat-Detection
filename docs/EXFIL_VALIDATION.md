# Data-exfiltration-like behavior — frozen validation design

## Gate recorded before controlled development replay (30 September 2026)

The existing passive path accumulates each source's observed forward bytes
over a 60-second bounded history and applies a fixed >20,000,000-byte rule.
`reverse_observed=false` means reverse data is unavailable: it must never
be represented as observed zero. The current ratio is per metadata event,
not a cumulative session ratio. Forward-from-source bytes are not guaranteed
to mean Internet egress without network-position context. No content or
intent is observed, so alerts may say **“behavior consistent with possible
exfiltration”**, never that confidential information was stolen.

Evaluate separately labelled, timestamp-ordered synthetic metadata streams
using a fresh production `Pipeline`. Scenario names, business purpose and
labels are never predictive features. A positive multi-event scenario is TP
only if its first `DATA_EXFILTRATION` alert precedes the final event; a
single-event large transfer may alert on that event. A positive with no
qualifying alert is FN; any alert on a benign case is FP, otherwise TN.
Record first-alert position, source forward bytes in the causal 60-second
history, observed ten-second byte rate, ratio value/status, reverse-data
availability and evidence wording. An independent causal reference must
agree with alert metrics. Training and runtime keep the same feature
definitions; the frozen model artifact is not refitted or modified.

The **development** matrix contains five positives: one large one-way
transfer, a sustained one-way transfer, a sustained transfer with explicitly
observed bidirectional metadata, a second one-way volume-only pattern, and
a slower sustained transfer. Six benign controls include a cloud backup
identical in visible metadata to the sustained one-way positive, a large
legitimate upload identical to the one-event positive, synchronization
identical to the bidirectional positive, replication/deployment identical to
the second one-way pattern, a smaller ordinary transfer, and an
inbound-heavy observed transfer. The paired cases deliberately test whether
passive volume/ratio alone distinguishes business purpose. An additional
unit edge case uses **explicitly observed zero reverse bytes**: its ratio
must be undefined, rather than computed by silently replacing zero with
one. This differs from missing reverse data, whose availability flag is 0.

Acceptance requires scenario recall >=80% (at least four of five), precision
>=95% and benign-scenario FPR <=2% (thus **zero** FPs with six negatives).
Every detected multi-event positive must alert before completion. The
source-history byte total and ten-second byte rate must be causal and
accurate; absent reverse traffic must yield no observed ratio; a positive
reverse count must yield the exact forward/reverse ratio; explicit zero
reverse must keep availability true but the finite ratio undefined. All
exfil alerts must use qualified wording and disclose when they rest on
volume alone. No threshold is relaxed or purpose-specific port/destination
exception is fitted after results are seen.

If development fails, no reserved evaluation set is constructed, inspected
or scored. A failed candidate is not promoted. Synthetic outcomes are not
production accuracy, and encrypted payloads are never decrypted. No active
query, probe, return-path dependency or inline mitigation is in scope.

## Results and decision

**Unresolved: the frozen development precision and FPR gates failed.** No
reserved evaluation set was constructed, inspected or scored. The initial
and corrected runs, with source hashes and event-level evidence, are in
`ml/exfil_development_initial.json` and `ml/exfil_development.json`.

| Controlled development result | TP | TN | FP | FN | Recall | Precision | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Before and after accounting/evidence fix | 4 | 2 | 4 | 1 | 80.0% | 50.0% | 61.5% | 66.7% |

The one-event 25 MB forward transfer alerted immediately. The 8×4 MB
sustained one-way case first alerted at event **6 of 8**, after 25 seconds:
24 MB observed source-forward bytes in the 60-second window and 1.2 MB/sec
over the ten-second rate window. The 6×5 MB one-way case alerted at event
**5 of 6**, after 16 seconds, with 25 MB and 1.5 MB/sec. Both kept
`reverse_available=0` and `observed_byte_ratio=null`, with explicit
volume-only wording. The explicitly bidirectional 8×4 MB case had
`reverse_available=1` and an exact per-event forward/reverse ratio of 40;
the frozen synthetic model alerted on its **first** 4 MB event, before the
20 MB volume rule. These are forward-byte patterns, not evidence of
confidential content or malicious intent. The slower 8×4 MB case was an FN:
its 15-second spacing kept at most 20 MB inside the 60-second window, and
the existing rule requires **more** than 20 MB.

The four FPs were cloud backup, a legitimate large upload,
synchronization, and replication/deployment. Each is visibly identical to
one positive case; their event-stream SHA256s match. A threshold, byte rate
or observed ratio cannot determine the business purpose of those pairs.
The small ordinary transfer and inbound-heavy observed transfer were TN.
The observed bidirectional ratio is per current event, not a cumulative
session ratio; a one-way capture never receives a fabricated reverse zero.

The separate 1,000-flow-summary stress check exposed a **correctable
accounting defect**: 25 MB arrived in 50 seconds, but the 512-event source
history retained only 12.8 MB and the old path emitted no exfil alert. A
bounded, source-specific one-second-bucket byte window now preserves the
full causal total independently of that history. It first alerts at event
**801 of 1,000**, when 20.025 MB has been observed; the ten-second
source-forward rate in evidence is 502,500 bytes/sec. The frozen model's
`egress_bytes` input remains the historical bounded feature to preserve its
training/inference contract; the **rule and alert evidence** use the new
accurate source window. Its bucket resolution can retain part of the oldest
second (under one second of overhang), which is disclosed by
`source_byte_window_resolution_ms=1000`. The window remains bounded by
source-state and 61 one-second buckets per source.

An explicitly observed **zero** reverse-byte count now retains
`reverse_available=1` but has `observed_byte_ratio=null` and status
`zero_observed_reverse_bytes`; dividing forward bytes by a substituted one
would not be an observed ratio. Missing reverse remains distinct, with
status `reverse_unavailable`. All exfil alerts now say **“behavior consistent
with possible exfiltration; content and intent unverified”**. One-way
alerts add the reverse-unavailable/volume-only note; zero-reverse alerts
state that a finite ratio is undefined. No output claims stolen data.

The refreshed 20,000-event benchmark passed the declared core processing
plus SQLite target at 6,083 metadata events/sec and 0.84 ms p95. This run
includes the preceding reconnaissance dedup fix and produced fewer alert
commits than the prior benchmark, so its throughput change must **not** be
attributed to the byte-window change. It excludes capture, HTTP, SSE and
browser delivery.

This task verifies causal forward-byte accounting and honest reverse-data
evidence, but **does not validate exfiltration intent** against legitimate
large transfers. The smallest next experiment is to acquire independently
labelled authorised and unauthorised transfers with passive destination or
host-baseline context that genuinely distinguishes purpose, then freeze a
new family/time-separated evaluation. No payload decryption, active lookup,
probe, return path, or inline action was added. Synthetic metrics are not
production accuracy.

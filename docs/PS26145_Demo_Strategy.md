# PS26145 — Final SIH Demonstration Design
**Scope:** The live demo sequence only — no architecture changes. This closes the "missing SIH demo strategy" gap (B6) from the final pre-blueprint audit.

**Honesty constraint carried forward from the capability-classification task:** encrypted-session malware's ML classifier was recommended for descoping due to its unresolved training-data gap. Step 7 below demonstrates the **rule-based detector only** for that threat (which does exist and function), with the ML gap stated plainly as future work — never presented as if the classifier exists when it doesn't.

**General device convention:** every live-triggered step has a validated, pre-recorded replay of the identical labeled scenario as its fallback, since replay mode uses the exact same pipeline code as live traffic (per the runtime-pipeline design) — a fallback is never a "fake" version of the demo, only a pre-executed run of the real system.

---

## 1. System Startup
- **Input scenario:** `docker compose up` on the demo host, using pre-built images (never built live, to avoid any internet dependency during judging).
- **What occurs internally:** all containers start (benign-generator, attack-simulator, victim, c2-tunnel-endpoint, capture, redis, pipeline, backend, frontend); the backend's Ingestion Adapter connects its Redis consumer group; health checks resolve.
- **Expected detector:** none — no traffic yet.
- **Expected dashboard output:** Overview loads with zero alerts, a live "listening" indicator active, throughput widget at zero, health check green.
- **Evidence shown:** `GET /api/health` returns healthy; Overview renders without an error state.
- **Failure fallback:** a pre-recorded screen capture of a successful startup, recorded during rehearsal, ready to cut to immediately.

## 2. Passive Traffic Ingest
- **Input scenario:** the benign generator begins sending a small volume of traffic across the internal Docker network.
- **What occurs internally:** the capture container receives mirrored/promiscuous traffic on an interface with **no IP address assigned**; Parser and Normalizer begin producing canonical records.
- **Expected detector:** none — this step proves plumbing, not detection.
- **Expected dashboard output:** Overview's throughput widget shows nonzero flows/sec; Live Detections stays empty.
- **Evidence shown:** a terminal pane showing the capture container's packet counter incrementing, plus a live `ip addr` check inside that container showing no IP — the visual proof of the read-only/no-return-path property.
- **Failure fallback:** switch to accelerated replay of a pre-recorded benign-traffic archive, exercising the identical pipeline code.

## 3. Benign Traffic
- **Input scenario:** sustained mixed benign traffic (iperf3 + Ostinato + a legitimate HTTPS session) runs continuously in the background for the remainder of the demo.
- **What occurs internally:** flows pass the full pipeline and correctly fail to cross any rule threshold or classifier decision boundary.
- **Expected detector:** all seven detectors evaluate this traffic; none fire.
- **Expected dashboard output:** Live Detections stays quiet; Overview's alerts-over-time chart stays flat at zero.
- **Evidence shown:** the flat chart itself — the moment to narrate the false-positive test suite from the verification strategy.
- **Failure fallback:** if a benign false positive fires (a known risk), state plainly which rule/feature needs retuning rather than glossing over it — this is more credible than pretending it didn't happen; if it threatens later steps, switch to the pre-recorded golden-path replay for the rest of the demo.

## 4. DDoS Detection
- **Input scenario:** presenter triggers an hping3 SYN flood from the attack-simulator against the victim, at a pre-tuned, rehearsal-validated intensity.
- **What occurs internally:** `dst_packet_rate`, `syn_no_completion_ratio`, and `src_ip_entropy_toward_dst` cross their thresholds within the short sliding window; the rule fires (primary), the Random Forest corroboration also fires, combined via the max-confidence hybrid rule.
- **Expected detector:** DDoS rule (primary) + Random Forest (corroboration).
- **Expected dashboard output:** a new alert appears in Live Detections within 1–2 seconds; severity high/critical depending on magnitude.
- **Evidence shown:** Alert Detail's traffic-rate chart, SYN-completion ratio, source-IP entropy, `sub_type = "SYN flood"`.
- **Failure fallback:** pre-recorded replay of the labeled DDoS experiment, guaranteed (per the verification strategy's known-outcome replay test) to reproduce the expected alert.

## 5. C2 Beaconing
- **Input scenario:** C2 beaconing genuinely requires a long observation horizon (hours) — not feasible live. This step deliberately uses **accelerated replay** of a completed C2 experiment archive, explicitly narrated as the correct, honest way to show this detector, not a shortcut — this is exactly what accelerated replay mode was designed for.
- **What occurs internally:** replayed beacon flows rapidly accumulate `periodicity_score_pair` and `destination_repeat_count_pair` state under accelerated pacing; the Random Forest/XGBoost classifier fires once sufficient repeat count is reached.
- **Expected detector:** C2 Random Forest/XGBoost.
- **Expected dashboard output:** alert with `threat_class = c2_beaconing` appears during the replay run.
- **Evidence shown:** the periodicity/inter-arrival visualization, repeat count, destination pair.
- **Failure fallback:** this step's "live" version already *is* a validated replay; if it fails, cut to a pre-recorded screen capture of this exact successful rehearsal run.

## 6. DGA / DNS Tunnelling
- **Input scenario:** two short back-to-back triggers — (a) a batch of DGArchive-sourced domain queries against the internal fake resolver, (b) a short dnscat2 session against the internal tunnel endpoint.
- **What occurs internally:** DGA — `domain_char_entropy`, `domain_ngram_score`, `nxdomain_ratio_host` computed and evaluated by the Random Forest/XGBoost model. Tunnelling — `query_length_avg_host`, `record_type_distribution_host`, `query_concentration_host_domain` evaluated by its Random Forest model.
- **Expected detector:** DGA Random Forest/XGBoost; DNS Tunnelling Random Forest.
- **Expected dashboard output:** two separate alerts, `threat_class = dga_domains` and `threat_class = dns_tunnelling`.
- **Evidence shown:** DGA — sample flagged domain strings plus NXDOMAIN ratio; Tunnelling — query-length/record-type breakdown.
- **Failure fallback:** pre-recorded replay of both labeled experiments; if the DGA traffic-generation pipeline fix isn't ready by demo day, fall back to replay-only for this step and state that plainly rather than attempting a live DGA trigger that might fail.

## 7. Encrypted-Session Anomaly
- **Input scenario:** a TLS session using a fingerprint pre-added to the demo's known-suspicious blocklist.
- **What occurs internally:** JA3 is computed from the ClientHello and matched against the static blocklist — the **rule's blocklist branch fires directly**. The ML classifier for this threat is not invoked, since it was recommended for descoping.
- **Expected detector:** Encrypted-Session Malware **rule** (blocklist branch) — explicitly not the ML classifier.
- **Expected dashboard output:** alert with `detector_type = rule`, confidence at the rule's staged high-confidence value for a direct blocklist match.
- **Evidence shown:** the JA3 hash and "known fingerprint match" evidence text.
- **Failure fallback:** pre-recorded replay of a labeled rule-trigger experiment. **Regardless of live or replay, the script requires the presenter to state plainly that the ML classifier for this threat is documented future work pending a resolved training-data source** — this caveat is part of the script, not a contingency to hide.

## 8. Reconnaissance
- **Input scenario:** a live port/host fan-out scan from the attack-simulator against the victim.
- **What occurs internally:** `unique_dst_port_count_src`, `scan_attempt_rate_src`, `flow_completion_ratio_src` cross their thresholds; the rule fires (primary), Logistic Regression corroboration.
- **Expected detector:** Reconnaissance rule (primary) + Logistic Regression (corroboration).
- **Expected dashboard output:** alert appears within seconds.
- **Evidence shown:** the scan fan-out visualization (targeted ports/hosts) and completion ratio.
- **Failure fallback:** pre-recorded replay of the labeled reconnaissance experiment.

## 9. Exfiltration
- **Input scenario:** a large, asymmetric outbound transfer from the "compromised-emulated" role to the C2/tunnel-endpoint role acting as receiver, toward a destination not previously contacted in the demo session.
- **What occurs internally:** `outbound_inbound_byte_ratio_flow` and `destination_novelty_flag` cross their thresholds; the Random Forest/XGBoost classifier fires.
- **Expected detector:** Data Exfiltration Random Forest/XGBoost.
- **Expected dashboard output:** alert with byte-ratio/volume evidence.
- **Evidence shown:** the byte-ratio/volume bar chart and the destination-novelty flag.
- **Failure fallback:** pre-recorded replay of the labeled exfiltration experiment.

## 10. Real-Time Alerts
- **Input scenario:** a callback moment, not a new trigger — the presenter switches to Live Detections and shows the cumulative feed from steps 4–9 having appeared live, via SSE, with no manual refresh.
- **What occurs internally:** the backend's Live Broadcast module fanning out over the SSE connection.
- **Expected detector:** none — this step aggregates the prior six.
- **Expected dashboard output:** all triggered alerts visible in chronological order, each with a severity badge.
- **Evidence shown:** the live "listening" indicator; the fact no page refresh occurred.
- **Failure fallback:** if the SSE connection visibly drops, point to the designed automatic-reconnect behavior and "reconnecting…" indicator as intentional, tested behavior (per the verification strategy's SSE test) — not a surprise. Worst case, manually load the Alerts history page to show the same data via the query-driven path.

## 11. Confidence + Severity
- **Input scenario:** open one high-severity alert (e.g., DDoS) and one lower-severity alert (e.g., reconnaissance) side by side.
- **What occurs internally:** the calibrated `confidence` value and the `severity` formula's output are both displayed.
- **Expected detector:** none — a data-contract demonstration.
- **Expected dashboard output:** both fields shown distinctly on each Alert Detail header.
- **Evidence shown:** the two numeric fields and severity-badge color-coding; if the day's actual alerts cooperate, point out a case resembling the alert-architecture task's own illustrative example (high-confidence-low-severity vs. medium-confidence-high-severity) — if not, explain the distinction verbally while pointing at the real fields on screen.
- **Failure fallback:** none required beyond the verbal fallback above — this step only needs an alert that already exists.

## 12. Supporting Evidence
- **Input scenario:** continue on the same open Alert Detail view(s).
- **What occurs internally:** the evidence object and template-generated explanation render.
- **Expected detector:** none.
- **Expected dashboard output:** the full evidence panel and human-readable explanation.
- **Evidence shown:** point out the explanation text is generated from the exact evidence values shown above it — the moment to state the template-based (not LLM-based) design choice and why it exists (zero fabrication risk in a security alert).
- **Failure fallback:** if one alert's evidence looks sparse, switch to a richer alert already present in the feed.

## 13. Historical / Replay Mode
- **Input scenario:** navigate to the Replay page and start a new session against a previously-unused labeled experiment, in **real-time-paced** mode this time (contrasting with step 5's accelerated mode, to show both pacing options exist).
- **What occurs internally:** the Replay Module validates the `experiment_id` against the lab manifest, instructs the pipeline's replay-mode ingest; resulting alerts flow through the identical ingestion path as live alerts.
- **Expected detector:** whichever threat that experiment represents.
- **Expected dashboard output:** the session status transitions `starting → running → complete`; a live alert count updates during the run.
- **Evidence shown:** the resulting alert's `experiment_id`/`replay_session_id` tagging, proving traceability.
- **Failure fallback:** a second, already-completed replay session's results pre-loaded and viewable via the session list, as an immediate fallback.

## 14. Throughput
- **Input scenario:** trigger the benchmarks module's accelerated-replay load generator for a 30–60 second burst at the committed target rate.
- **What occurs internally:** the pipeline processes the accelerated load while the Metrics module samples throughput continuously; detectors continue running normally in the background (worth mentioning explicitly).
- **Expected detector:** none directly — a performance demonstration.
- **Expected dashboard output:** the throughput readout climbing to and holding at the committed **≥2,000 flows/sec** target from the verification strategy.
- **Evidence shown:** the live measured number, explicitly stated as matching the number recorded in the verification-strategy benchmark run — not a live-only claim.
- **Failure fallback:** if live performance underperforms on demo hardware, present the actual pre-recorded benchmark result as authoritative, framing the live run as illustrative, not as the sole source of the number.

## 15. Alert Latency
- **Input scenario:** re-trigger a fast, clean scenario (DDoS) with a visible on-screen timestamp/stopwatch overlay.
- **What occurs internally:** end-to-end alert latency measured from Passive Ingest arrival to Alert Output emission.
- **Expected detector:** DDoS (rule + RF hybrid).
- **Expected dashboard output:** the alert's `detection_timestamp` shown beside the triggering event's `timestamp`, with the gap visibly small.
- **Evidence shown:** the two timestamps side by side, comfortably under the committed **p95 < 2 second** target.
- **Failure fallback:** cite the recorded benchmark number from the verification strategy as authoritative if live conditions are noisier than rehearsal.

---

## Demo Preparation Checklist

- [ ] All Docker images pre-built and tested at least 24 hours before the demo — never build live.
- [ ] Every scenario's trigger command/script rehearsed at least three times on the actual demo hardware, not just a development machine.
- [ ] Every "live-triggered" step has its matching pre-recorded replay archive and, separately, a pre-recorded screen-capture video ready to cut to instantly.
- [ ] The committed performance numbers (≥2,000 flows/sec, p95 < 2s) are pulled from an actual verification-strategy benchmark run completed before demo day, not projected.
- [ ] A full dry run of all 15 steps, timed, with a target total runtime comfortably under the judging slot's time limit.
- [ ] Demo host's network settings double-checked to confirm the internal Docker network has no accidental egress (a last static check before judging, not just at design time).
- [ ] Laptop/host fully charged or on continuous power; no reliance on venue Wi-Fi at any point in the sequence.
- [ ] A visible, rehearsed line ready for the encrypted-malware caveat (step 7) so it's delivered confidently, not apologetically.

## Pre-Recorded / Replay Fallback Strategy

Every live step's fallback is a **validated replay of the identical labeled scenario**, never a scripted-looking fake — because replay mode runs through the exact same pipeline code as live traffic (per the runtime-pipeline design), a fallback demonstrates the real system, just on pre-captured input instead of a live trigger. A second-tier fallback (a pre-recorded screen-capture video of a successful rehearsal run) exists for the rare case where even replay fails live (e.g., a display/projector issue) — the video is never a substitute narrative, only a substitute *display* of something that was genuinely produced by the system during rehearsal.

## Metrics to Display

- Live throughput (flows/sec), continuously visible on Overview throughout the demo.
- End-to-end alert latency (per-alert `detection_timestamp` minus event `timestamp`), surfaced explicitly in steps 14–15.
- Alert count by severity, visible on Overview at all times.
- Queue depth / drop count, available if a judge specifically asks about backpressure behavior (not part of the core script, but ready).

## Points Judges Are Likely to Question

- **"Why encrypted-session malware only has a rule detector, not ML?"** — answer honestly with the data-gap explanation and the descoping rationale from the capability-classification task; this is a stronger answer than pretending it's fully solved.
- **"How do you know you're not decrypting TLS/QUIC traffic?"** — point to the architectural-compliance test from the verification strategy (a session processed successfully with no private key ever available to the pipeline).
- **"How do you avoid false positives on real, messier production traffic?"** — reference the false-positive test suite (§2 of the verification strategy) and be candid that lab-generated traffic has known domain-shift risk versus real-world traffic (already flagged in the dataset-evaluation task).
- **"What's your actual throughput number, and how was it measured?"** — the committed figure and the accelerated-replay benchmark method (§7 of the verification strategy) should be ready verbatim, not reconstructed on the spot.
- **"Why rules AND ML, not just one?"** — this is a good moment to walk through the rule-baseline task's own finding: rules go furthest on DDoS/reconnaissance, ML is clearly necessary for C2/encrypted-malware, and the rest sit in between — a scientifically grounded answer, not a hedge.
- **"Does this scale beyond one host?"** — acknowledge the documented Redis Streams → Kafka upgrade path and multi-host production architecture from the deployment task, while being clear that horizontal scaling was deliberately out of scope for this prototype.
- **"Is your lab traffic realistic?"** — acknowledge the domain-shift risk already documented in the dataset-evaluation task honestly rather than overselling lab-generated traffic as equivalent to real-world traffic.
- **"How do you know your model wasn't tampered with?"** — reference the model-integrity hash-check (security review, MVP-classified) and, if built, the lightweight tamper-evident alert hash-chain.

---

**No architectural component has been changed in this document** — this defines only the demonstration sequence, preparation, and fallback strategy for the system already designed and audited.

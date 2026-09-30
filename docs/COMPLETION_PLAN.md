# Univect completion plan

Updated 29 September 2026. The governing deliverable is the working passive
streaming prototype described in the owner's screenshots, as mapped in
[Expected solution](EXPECTED_SOLUTION.md). This plan preserves that scope.

## Definition of done

- Read-only simulated/exported metadata and supported captures feed incremental
  feature extraction, inference, persistence and the Monitor without a return path
  to monitored hosts. No payload decryption or mitigation is introduced.
- Every required threat category has an executable positive scenario, realistic
  benign counterexamples, standardized evidence and an honest validation report.
- Model documentation records sources, features, splits, thresholds, recall,
  precision, false positives and visibility limitations. Failed candidates remain
  disabled; synthetic accuracy is never presented as deployment accuracy.
- The core + SQLite benchmark meets the declared 2,000 metadata events/sec and
  p95 <50 ms target. A separate measurement covers API-to-SSE alert delivery,
  using a predeclared loopback p95 <1,000 ms target, excluding browser rendering.
- Dashboard controls, uploads, errors, reconnects, navigation and responsive
  layouts work. Backend tests, TypeScript and the production build pass.
- A clean checkout can follow the README to run the app and reproduce a complete
  demonstration. Source, reports and documentation are pushed to the repository.

The existing software meets most structural requirements. Detection generalization
is the main remaining risk. This is a local prototype; production authentication,
distributed services, additional dashboards and physical diode certification are
separate work, not prerequisites invented for this plan.

## Ordered work

| Phase | Work and deliverables | Completion check | Status |
| --- | --- | --- | --- |
| 1. Establish a reliable baseline | Audit stream accounting, causality, bounded state, parser/API errors and model activation. Add regressions for reproducible failures; refresh reports after fixes. | All backend tests pass; raw-packet floods and flow summaries retain their correct rates; no stale report is labelled current. | Completed first pass; 89 tests/build pass |
| 2. Improve DGA | Diagnose short/pronounceable families and benign DNS false alarms; reserve new evaluation data before tuning; fit using training/validation only; verify portable export and runtime cost. | Existing project gates: recall >=80%, precision >=95%, domain FPR <=2%, separate benign-DNS FPR <=2%. Promote only after passing with a documented evaluation scope. | Unresolved: weighted candidate passes validation, but reserved domain and separate benign-DNS evaluations are unavailable; candidate and current public model remain disabled. See `docs/DGA_WEIGHTED_CANDIDATE.md`. |
| 3. Improve DNS tunnelling | Use genuinely visible, labelled DNS queries; cover A/AAAA as well as TXT/NULL and multi-label encodings; compare entropy, length, novelty and causal query behavior with benign CDN/telemetry traffic. | Incremental alerts before scenario completion, protocol/parser regressions, labelled recall/FPR report. No forced alerts on unlabelled downloaded captures. | Visibility audit and opt-in development comparison complete. Formal gate frozen, but promotion blocked by absent independent labelled full-DNS evaluation (`docs/DNS_TUNNELLING_FORMAL_VALIDATION.md`); candidate remains disabled. |
| 4. Validate remaining categories | Test SYN/UDP/spoofed floods, periodic C2 versus periodic benign clients, host/port sweeps, directional volume/ratio anomalies and encrypted-session metadata. Fit any replacements with shared causal runtime features. | Per-category confusion counts and evidence; separate family/time splits where labels permit; disclose unavailable reverse traffic and encrypted visibility. | SYN-flood controlled functional gate passed (`docs/SYN_FLOOD_VALIDATION.md`). UDP flood development validation is unresolved: four of six labelled benign high-volume cases still alert; reserved evaluation was not opened (`docs/UDP_FLOOD_VALIDATION.md`). Spoofed-source indicators cannot distinguish matched genuinely distributed clients (`docs/SPOOFED_SOURCE_VALIDATION.md`). C2 beaconing fails against periodic benign clients and slower/rotating beacons (`docs/C2_BEACON_VALIDATION.md`). Reconnaissance fan-out is causal and horizontal alert duplication was fixed, but authorised scanners cause three of six benign scenarios to alert (`docs/RECON_VALIDATION.md`). Exfil-like source-byte accounting and reverse-data evidence were corrected, but matched legitimate transfers cause four of six benign scenarios to alert (`docs/EXFIL_VALIDATION.md`). Independent capture transfer and encrypted-session metadata validation remain pending. |
| 5. Verify complete integration | Measure API ingestion -> persisted alert -> SSE delivery; exercise disconnect/resume, replay stop/error, invalid uploads, restart persistence and empty/error states. Recheck Monitor on desktop/tablet/mobile. | Integration tests pass; recorded loopback delivery measurement; no console/TypeScript/build errors; refreshed throughput benchmark passes. | Partially complete: direct API/SSE and Monitor smoke checks pass; final full UI pass remains |
| 6. Package the demonstration | Prepare a concise demo sequence and requirement checklist; pin source/model/report provenance; document setup, data preparation and remaining limits; commit and push. | Fresh-install smoke check, complete demonstration of all required categories, clean Git state and matching remote. | Pending |

Phases may overlap when work is independent. A failed model gate is an unresolved
detection task, not permission to relax the gate. Gate percentages above are our
project acceptance criteria, not numbers mandated in the screenshots. New quality
criteria for other models must be recorded before examining their evaluation set.

## First task selected

The audit found that the 10-second global rate window retains only 4,096 events.
For individual packets, that caps the displayed packet rate at 409.6/sec even when
the observed rate exceeds the 1,000/sec DDoS rule threshold. This can hide genuine
raw-packet floods while synthetic aggregated-flow examples still pass.

**Completed:** bounded time aggregates preserve packet and byte totals. Rate-window
resolution and entropy truncation are disclosed, and raw-packet regressions pass.
The 20-feature model contract and passive architecture are preserved. Details are
in [Streaming reliability](STREAM_RELIABILITY.md).

## Progress from this implementation pass

- Fixed the raw-packet rate cap and overflow-entropy grouping; all 89 tests pass.
- Frozen-model lab regression is unchanged; both fitted artifacts are untouched.
- Replayed all 14 captures / 609,583 parsed IP packets and refreshed source hashes.
- Core + SQLite: 3,027 events/sec, p95 1.08 ms. Direct loopback API-to-SSE: p95
  250.09 ms with 100/100 alerts received, persisted and correctly resumable.
- Production build/TypeScript and restarted Monitor smoke checks pass. Original
  analyst history remains 130 records.
- Phase 2 is next. DGA, tunnelling and remaining threat-quality validation are
  still open; software reliability results do not close those tasks.

## Current evidence to preserve

- 81 backend tests and the production website build passed before this phase.
- Current DGA candidate: 76.77% recall / 1.68% FPR in inspected development
  comparisons; second DNS-reference FPR 2.34%. It remains disabled.
- Saved baseline benchmark: 2,514 metadata events/sec, processing/persistence p95
  1.28 ms. These are core measurements, not browser-delivery measurements.
- Existing raw datasets and the dashboard's alert history must remain intact.

Track completed work and measured results here as each phase progresses. Avoid
adding infrastructure or dependencies without a concrete requirement.

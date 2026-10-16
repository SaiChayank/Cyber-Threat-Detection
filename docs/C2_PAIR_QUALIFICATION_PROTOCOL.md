# T23 C2 development-pair qualification — pre-value protocol

Frozen 17 October 2026 against baseline 20f0c23. Qualification only, not training,
feature implementation, detector scoring or a new accuracy evaluation.

Inspect existing reports and publisher documentation only until provenance passes.
Inventory at most four plausible sources in this bounded screen; restrict to
primary publisher records/repositories/papers. Previously exposed TQH metadata
and acquisition reports may be reused; do not parse new labels/packets/flow tables.
All consulted sources are development leads, never untouched final evaluation.

Required before packet/annotation values are opened:
- Explicit capture-data permission, version, exact original artifact URL/member,
  original-file SHA256 and complete supported classic Ethernet PCAP v2.4/linktype1.
- Producer run boundaries, original UTC timestamps/timebase, endpoint/direction
  mapping, framework execution and independently established C2 intent. A generic
  infected-host label or a timing/JA3 classifier is insufficient contact truth.
- Producer contact or exchange annotations with timestamps and tuple/UID/run joins,
  or an independently documented producer event-to-contact mapping. Flow starts,
  handshakes, packets and C2 callbacks are different units; never equate them solely
  because they recur. Distinguish configured schedule from executed contact times.
- An actual named benign periodic application (health checks/telemetry/polling),
  its authorized workload/run records and original contact annotations, on a
  matching transport/application-service class (e.g. HTTPS). Port equality alone
  proves neither service identity nor benign intent. Do not rewrite ports or time.
- Both sides from a comparable capture environment, or explicit environment
  differences disclosed so source identity cannot serve as the separator.
- At least nine independently annotated contacts per side, permitting first-eight
  evidence before the last contact. No special demo interval or horizon exception.

Only if those prerequisites pass, bind the exact pair and annotation/artifact
hashes before reading packet values. Keep all producer-labelled contacts/run
intervals; no choosing by Univect output. Original inter-contact interval IQRs
must intersect (endpoints inclusive, including matching fixed intervals); report
all intervals and distributions, jitter, counts, timestamp gaps and exclusions.
This is a fixed data-matching screen, not a detector threshold or proof of intent.

Then compare only existing forward passive metadata/causal histories: which
packets/records correspond to producer contacts, sizes, intervals, history counts,
missing fields and surviving collisions. No prediction, fitting, model/rule
ablation, gate/threshold/horizon changes, packet generation, external DNS/reputation,
return-path dependency or payload decryption. No new format/parser support.

Preserve all fourteen controlled development scenarios and historical failure:
TP3/TN6/FP2/FN3, precision60%, recall50%, FPR25%. Frozen quality gates remain
recall>=80%, precision>=95%, FPR<=2% plus early jitter/non-demo/rotation coverage.
This pair can never establish promotion or substitute for independent evaluation.
Preserve all other detector partitions, raw datasets, artifacts and alert history.

Missing/ambiguous provenance or contact/application labels => NOT QUALIFIED;
record unknowns and stop before values. No new recipient/message or mailbox access
is authorized by this source screen. DoD requires a reproducible qualified pair,
contact mapping and measured overlap, otherwise explicitly report BLOCKED.

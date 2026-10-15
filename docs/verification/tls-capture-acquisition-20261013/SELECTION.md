# Development acquisition selection

Chosen from the publisher's normal authenticated browse listing before reading
new capture/CSV values. All acquired/inspected files are development-only and
cannot later be represented as untouched final evaluation.

- Raw positive source: `MaliciousDoH-dnscat2-Pcap-001-600.zip`.
- Raw benign source: `BenignDoH_NonDoH-Firefox-AdGuard.zip`.
- Publisher annotations: `MaliciousDoH-CSVs.zip` and
  `BenignDoH-NonDoH-CSVs.zip`.

Choose these by source/tool/browser and filename, not predictive performance.
Keep complete archives where download finishes; per-file cap 8 GiB for raw
archives, 512 MiB for annotation archives. Interrupted/oversized partial downloads
are never called complete source artifacts. No executable/keys are extracted.
Archive extraction is developer data preparation only, never an upload feature.

For first qualification, inspect up to the first three positive PCAP members
in sorted filename order and the first 200,000 packets of one benign PCAP member.
Record bounded-scan scope explicitly. Join existing publisher annotations only
by observed endpoint tuple, capture timestamps and supported flow-time windows;
ambiguous or conflicting joins stay unlabelled. Ground truth does not come from
our detector, hostname entropy, a fingerprint or the filename alone.

Verify complete ClientHello boundaries and exact raw packet position/time using
the existing parser. Do not reassemble or decrypt in the runtime and do not move
completed-session features to earlier timestamps. Count unknown/unsupported
observations and declared capture clipping. This is a small capability cohort,
not a malware generalization experiment or a passing training-data gate.

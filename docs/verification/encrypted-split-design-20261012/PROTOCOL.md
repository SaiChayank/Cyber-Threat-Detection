# Sample/capture-aware encrypted development split design

Recorded 12 October 2026 before constructing components. Metadata only; no feature
columns, inference, training, new datasets or reserved evaluation reads.

Use existing permitted winapps/malware archives with verified source hashes.
Link observations sharing any exact family/app group, sample ID or Parquet capture
member. A connected component is indivisible. Components touching an old
historical-test group are quarantined entirely; they never become development.
Unlabelled rows cannot supply positive/benign truth. SOHO remains excluded.

Assign remaining components once by SHA256 of sorted component identifiers:
modulo 10 buckets 0–5 training and 6–9 validation. No salt search, row randomization,
family relabelling, component fragmentation or reassignment to improve counts.

Technical acceptance: zero sample/member/group overlap across assigned partitions;
both label classes present in both training and validation; no historical-test
component assigned to development. This is a split-integrity gate, not classifier
quality acceptance or a claim that one component is statistically sufficient.
Existing recall/precision/FPR/timing gates remain unchanged.

Record source/protocol hashes, component/member IDs and counts, assignments,
quarantine, overlap checks and feasibility. Preserve the old split and reports.
If either class lacks development support, mark this design infeasible and perform
failure analysis only. Do not train or weaken isolation requirements to force a pass.

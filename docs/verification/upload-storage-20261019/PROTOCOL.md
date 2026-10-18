# Upload temporary-storage failure handling

19 October 2026 IST; baseline `5302020`. Narrow T50 precursor. Use only disposable
databases and generated classic-PCAP unit fixtures; no raw datasets or reserved
observations. Reproduce temporary-file allocation, write and close/flush failures
with ENOSPC/EACCES before changing code. Preserve pre-existing analyst records and
causal/replay state when upload staging fails.

Required behavior: HTTP 503 with actionable generic storage feedback, no internal
path in the response, staged-file cleanup when filesystem deletion is permitted,
healthy API and successful next valid upload. Existing malformed/oversized/cancel
semantics, 16 MiB bound and read-only source handling remain unchanged. No new
formats, URLs, archives, services or dependencies. A filesystem that refuses
deletion cannot be repaired by this handler; never claim guaranteed cleanup there.

If a defect is measured, make the smallest change in the existing upload staging
block and add exact regressions. Run upload/replay/recovery tests, then full backend
and frontend typecheck/build. Before updating an affected demo source-provenance
pin, prove all frozen fixture hashes and nine expected traces are unchanged.
Preserve old manifest references and initial failure results. Model/research/data
gates stay unchanged. Use dated delivery output if the shared API changes.

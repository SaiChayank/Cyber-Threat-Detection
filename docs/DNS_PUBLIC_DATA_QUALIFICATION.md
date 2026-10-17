# Downloaded public DNS data qualification

17 October 2026; baseline `b5ad602`. **NOT QUALIFIED FOR THE FROZEN EVALUATION.**
Inspection/decision package complete; usable evaluation-data Definition of Done
does not pass. No model, rule, threshold, parser, scorer or runtime flag changed.

## Inspected and exact scope

Reviewed the existing source screen, acquisition manifest/report, current PCAP
global-header validator and frozen DNS scorer/contract. Before ZIP member access,
[the inspection protocol](DNS_PUBLIC_QUALIFICATION_PROTOCOL.md) and protected-file
snapshot were saved. Both original ZIPs were rehashed against the acquisition
SHA256s; originals are unchanged. Metadata catalogues and one bounded README were
read. One nested ZIP was copied opaquely to a fixed ignored workspace, with full
size/CRC/SHA256 verification, solely to read its central directory.

No CSV headers/rows, query values, packet records/times, fingerprints or model
binary contents were read. No upstream code, archive extraction commands writing
data members, model prediction, training, replay or reserved scoring was run.
Reading publisher README examples is recorded documentation exposure, not a
claim that those examples can later be untouched evaluation cases.

## DNSTunnel2026: actual contents and finding

Original `DNSTunnel2026.zip` has exactly three catalogue entries:

- `Archive.zip`, 450,772,657 uncompressed container bytes.
- `dga_quantized_model.bin`, 52,054,243 declared bytes; left unopened.
- `Readme.md`, 16,617 bytes; reviewed as documentation only.

The inner ZIP catalogue contains `train.csv` (3,604,938,364 declared bytes),
`test.csv` (901,238,480), and two Apple `__MACOSX/._` resource-fork entries.
No original capture, original client-question log or independent session/run
annotation manifest is listed at either inspected level. CSV filenames differ
from the README's `train_data.csv`/`test_data.csv`; this is a documentation naming
discrepancy, not permission to inspect or adopt those splits.

README describes processed company/domain windows, SmoothFlow-generated positives
and behavior/reputation-supported labels. It does not establish independently
joined dnscat2/iodine sessions with original source/time/QNAME/QTYPE histories or
all five benign controls. Its published row counts are publisher claims, not
locally measured counts. Actual CSV schema and rows remain uninspected, so this
review does not certify what additional columns they might contain. No complete
frozen-contract input/label chain is established. The bundled model does not
replace or qualify any Univect DGA/DNS artifact.

**Disposition:** unqualified research intake. Upstream train/test names are not
our training/validation/reserved partition; source/family/run leakage prevention
cannot be certified from names alone. All project role assignments remain null.

## UMA benign captures: actual contents and finding

The original archive catalogue lists exactly **45 nominal `.pcapng` members**,
without directories or bundled run/session annotations, README or client-query
logs. Names cover Admin/Gamer/Web, 5m/15m/1h and suffixes 1–5. This matches an
apparent profile grid, not proof of executed run independence, actual capture
duration, original UTC time or independent DNS session counts. A capture can
contain multiple sessions; 45 files cannot be substituted for a session total.

All 45 entries declare ZIP compression method **9**, without the ZIP encryption
flag. Python's standard `zipfile` raised `NotImplementedError` before reading the
first selected header. A preregistered pilot using installed Windows `tar.exe`
also returned zero header bytes and a nonzero exit. Its generic damaged-archive
message is not proof that the publisher archive is corrupt. The original ZIP
still matches its publisher checksum and acquisition SHA256.

No new decoder was installed and no conversion performed. **Actual capture magic,
link type, snaplen and original packet timestamps remain UNVERIFIED.** Filename
extensions suggest PCAPNG, which the frozen runtime excludes, but are not treated
as observed magic. Further member reads stopped. Complete QNAME/QTYPE, observed
query timing, client/source joins, independent benign session labels and the five
DNS application categories remain unverified. General benign profile descriptions
do not establish those category/session labels.

**Disposition:** unqualified research intake, no runtime use or role assignment.
Compression compatibility alone would not resolve the missing original session
and category provenance, nor authorize adding a PCAPNG parser.

## Qualification decision and unchanged criteria

Both sources retain their reviewed open CC BY 4.0 publisher metadata and original
attribution in the acquisition manifest. Rights/whole-archive integrity pass;
complete supported input, independent joined session truth, required tool/benign
coverage and eligible whole-run partitions do not pass. Label missing requirements
as unestablished, not zero-valued data or fabricated negatives. No cross-role value
overlap check is claimed because no rows were accessed or roles assigned.

Original gates remain >=20 independent positives/>=50 benign sessions, dnscat2 or
iodine, five benign strata, recall >=80%, precision >=95%, FPR <=2%, all TPs before
completion and >=90% by query 10 AND <=10 seconds. Zero eligible final sessions
are assigned; actual independently qualified session counts remain unknown.
No confusion counts, accuracy, latency or throughput were measured here.
The DNS candidate stays disabled and reserved readiness stays false.

## Verification, files and next step

Evidence in `verification/dns-public-qualification-20261017/` includes outer/inner
catalogues, selections saved before member reads, the README snapshot, copied
container identity, explicit unsupported-header attempts and integrity checks.
`data/dns_public_qualification.json` is the machine-readable decision. New files
are documentation/manifests/evidence only; earlier frozen reports remain historical.
No reusable diagnostic module or application bug fix was added, so no new tests,
backend suite or frontend build was needed. Metadata/selection/integrity checks
are reported separately in `checks.json`; no functional-test pass is invented.
All **23 qualification/integrity checks pass**, with **114 protected file hashes**
and both original archive hashes unchanged. Passing record-integrity checks does
not turn the unresolved input/label requirements into a qualification pass.

**Exactly next:** review the UMA producer's publicly available executed-run
manifests or original client-query-log exports, if any, before further capture
values. Require original source/time/namespace joins and DNS category provenance;
if absent, record the missing bundle rather than install a decoder merely to seek
passing traffic. A separately scoped archive-compatibility task could confirm
headers later, but cannot substitute for those labels. No publisher message,
future experiment, scoring or architecture expansion starts automatically.

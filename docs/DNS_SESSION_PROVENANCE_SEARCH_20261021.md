# DNS executed-session evidence — 21 October 2026

**Checksummed public data acquisition and metadata verification PASS. Independent
DNS-tunnelling accuracy validation remains BLOCKED; the candidate stays disabled.**
Baseline `905f40a`. No detector, threshold, feature, model, runtime, gate, analyst
history or previously frozen input changed. No reserved pass was consumed.

## What was inspected

Reviewed the current execution plan, frozen DNS contract/scorer, earlier public
source and Burgos verification packages, and the scoped synthetic accuracy report.
Then screened four additional public collections under the [pre-value protocol](verification/dns-session-provenance-search-20261021/PROTOCOL.md).
Useful subsets may be combined across sources; a collection need not supply the
whole cohort. Public documentary retrieval used the existing bounded fetcher;
no account forms, email, private supplements, new external messages or lab work.

There are 29 verified documentary HTTP receipts, three disclosed retrieval
failures and eight verified immutable Git document blobs. The existing
[Korving issue](https://github.com/Korving-F/dns-tunnel-dataset/issues/3) had zero
public comments at this one-time check. This is not ongoing mailbox/issue polling.

## New useful evidence: AIT

[AIT-LDS v2.1](https://zenodo.org/records/19483937), released 9 April 2026, supplies
eight simulated enterprise testbeds, actual executed-tool logs and per-line
attack annotations. Its record declares **CC BY-NC-SA 4.0**. Use with attribution;
raw artifacts remain ignored and are not redistributed in Git. This is controlled
lab provenance, not production-generalization evidence.

Downloaded `russellmitchell_no-pcaps.zip`, exactly **522,084,364 bytes**, to
`data/raw/ait-dns-intake-20261021/`. Whole-archive integrity independently rechecked:

- Publisher MD5: `abb43a46c70939ad9f98669e3510d2b7`.
- Local SHA256: `51a03f51daea0fbbdcfe9b8abe0dbbe10633716f4f98074f861204a162ee1978`.
- Directory: 14,898 entries. Complete directory bytes are cached outside Git,
  with a tracked hash and selected-member inventory.

The prior 1 MiB directory reader correctly refused this 2,222,342-byte directory.
The server supplied no ETag/Last-Modified for conditional range identity. Rather
than relax identity verification, acquired the complete opaque archive and checked
its published checksum before member access. A slow sequential prefix was retained
and completed in eight bounded, exact-length non-overlapping range streams. Full
checksum verification covers the prefix and all ranges; no partial was trusted.

The actual archive uses `dataset.yaml` and `processing/config/servers.yaml`,
whereas the publisher's explanatory text uses `.yml`. Corrected exact metadata
paths were frozen before access; initial absent `.yml` matches are not claimed
to mean missing simulation/host metadata. Selected members passed ZIP CRC checks.

The original receiver log contains 20,054 execution records, 19,954 receive
events, 31 distinct saved-file completions and 32 referenced files. First/last
receive timestamps are 20 January 2022 12:48:27.531129 UTC and 24 January
13:50:03.249096 UTC. Of the receive events, 2,306 precede the declared simulation
start of 21 January; 17,648 fall inside its four-day interval. These are receiver
events, **not DNS question counts**. The listener start/stop and a saved filename
are not independent client-session boundaries or causal query visibility.

This is a real improvement over having only archive/scenario names: original
execution timing and transfer-completion evidence is now locally available and
checksummed. It does **not** establish 31 independent experiments, a complete
receiver-to-client/question join, original question visibility or five benign
application categories. All transfer files remain one run group pending evidence
of actual session independence. DNSteal also does not fill the required
dnscat2/iodine coverage. Resolver logs, label rows, downloaded payload files and
upstream lab programs remain unopened/unexecuted. No evaluation role assigned.

## Other reviewed sources

**Splunk attack_data:** pinned revision
`eb43d0b905df274a7c105573ce7b2ea9e2b6f413`, Apache 2.0. The six reviewed
[DNS/exfil scenario descriptions](https://github.com/splunk/attack_data/tree/eb43d0b905df274a7c105573ce7b2ea9e2b6f413/datasets/attack_techniques/T1071.004)
reference Sysmon/PowerShell host logs. Their metadata does not establish original
QTYPE/client-question/session joins. Manually generating long DNS names does not
prove a completed tunnel. No log contents/LFS objects downloaded. This finding
applies to the reviewed scenarios, not every dataset in the repository.

**UWF-ZeekData22:** the [producer](https://datasets.uwf.edu/) states CC BY 4.0.
Its [attribute schema](https://datasets.uwf.edu/tables/table2.html) documents
query/source/type/time fields, and public CSV/Parquet indexes exist. Reviewed
pages do not establish the required executed-tool session joins or independently
attributed benign controls. Generic T1048/T1071 annotations and protocol tunnel
logs are not proof of DNS exfiltration. Both linked DNS description URL variants
returned 404; the separate schema remains available. No CSV/Parquet rows opened.

**Multi-Source Cybersecurity Logs:** the [v1 paper](https://arxiv.org/html/2606.18190v1)
reports 870 sessions, but its reviewed links provide no actionable public dataset
download or dnscat2/iodine/client-question joins. A paper's CC BY licence does not
by itself establish dataset permission. No author request was sent and no paper
accuracy figure was adopted as project evidence.

These scoped negative findings are not proof that no adequate public source
exists anywhere. Retrieval errors, reviewed-source gaps and true unsupported
observations remain separate findings.

## Changes, tests and preservation

Added the source manifest `data/dns_session_provenance_search_20261021.json`, this
report, dated documentary/download/summary/check scripts and receipts, and
`tests/test_dns_session_metadata_intake.py`. Updated only current-plan/progress
pointers. The full archive, metadata originals, transfer prefix/segments and full
directory are ignored raw cache artifacts. No product behavior changed.

Seven new tests cover changed/full HTTP responses, encoding/length failures,
metadata-only access and ambiguous selection. **36 targeted tests pass** including
the earlier intake and Burgos regressions. An initial test-fixture ROOT mismatch
was corrected; no production defect or weakened assertion. Full backend/build
were not rerun because this package changes no shared application behavior; prior
suite/build claims retain their original dates and scope.

Offline checks confirm all 130 protected original hashes, both previously acquired
captures, three frozen packages and all 23 DNS contract source pins are unchanged.
Documentary examples and the overbroad pre-existing-development search are
explicitly disclosed in [the exposure record](verification/dns-session-provenance-search-20261021/EXPOSURE.md).
No source is silently reclassified as an untouched reserved set.

## Decision and exactly next

Before/after: qualified reserved roles **0 → 0**; independent accuracy **NOT
ESTABLISHED → NOT ESTABLISHED**. No new confusion counts, detector quality or
performance claims. Metadata acquisition DoD **PASS**; formal feature-validation
DoD **BLOCKED**, release **NOT READY**. Candidate remains disabled.

The unchanged final requirements are >=20 independent positive/>=50 benign
sessions, dnscat2/iodine, all five benign categories, original complete causal
questions and frozen disjoint roles; recall >=80%, precision >=95%, benign-session
FPR <=2%, every TP before completion and >=90% of TPs by query 10 **and** 10 seconds.
No subset substitution or gate reduction is justified.

**Exactly next:** qualify a publicly supported receiver-to-original-client/run/
question mapping plus independent session/application annotations, starting with
this AIT ledger. Establish that evidence before resolver values or final scoring;
do not promote saved files, arbitrary time slices or generic normal traffic into
independent sessions/five benign controls. If those annotations cannot be
established publicly, keep the source partial and the final gate blocked.

# Burgos first benign capture: acquisition and conditional visibility protocol

21 October 2026. Baseline `26256d7`. User requests completion of the next
verification. Preserve all existing inputs, analyst history, runtime/artifacts,
evaluation gates and partitions. No candidate inference, training or activation.

Stage A, before native capture bytes: use only the already inventoried public ZIP
at DOI `10.71486/dgza-t550`, archive size 1,269,092,760, Last-Modified
`Fri, 07 Nov 2025 12:30:49 GMT`, pinned central-directory offset 1,269,092,427,
length 311 and SHA256
`b0e8df4a6177c9111c6ca24ca33709626f1fd6e5eed66d5a8b280861fa756887`.
Select only exact member `benign_first_cap.pcap`, compression 8, CRC32
`5bd6ba90`, compressed bytes 8,021,093, original bytes 8,852,172. Never use an
archive name as a destination path. Only fixed ignored intake paths are allowed.

Require HTTP 206, exact Content-Range/length/identity, identity encoding and
If-Unmodified-Since on every range (<=1 MiB each). Reject changed directory,
unsupported ZIP structure, encryption, unexpected member/length/compression,
excess output, bad deflate end state or CRC. Do not acquire the second >1 GB
benign member or malicious member, extract filesystem trees, install decoders,
convert capture format or fetch the full archive. Persist verified original
member bytes and local SHA256. This verifies selected-member CRC plus conditional
source continuity, not a producer-published full-archive SHA256.

After full selected-member integrity passes, read the first 24 bytes using the
existing native header validator. Only classic PCAP v2.4 Ethernet/linktype 1 is
supported. If native format/link type is unsupported, STOP before packet records
and record the compatibility blocker. Do not relabel or silently convert it.

Stage B is allowed only after Stage A passes. Before packet records, freeze a
separate exact visibility script/source identity and neutral reporting plan:
original capture order/timestamps, truncation/late ordering, complete DNS/53 client
questions, QTYPE counts and original source-level coverage. Use the current
parser, no DNS lookups, source reputation, TLS/QUIC payload decryption, detectors
or model. Do not print actual query text or invent application categories/session
boundaries. Such counts are qualification evidence, not quality metrics. All
inspected inputs remain non-reserved pending explicit full-role/disjointness
qualification; minimum 20/50 independent sessions and all five controls remain.

Test bounded source acquisition using controlled byte fixtures, including wrong
ranges/identity, altered directory/member, short/long data, bad CRC/deflate,
unsupported headers and existing-file preservation. Verify all 130 protected
originals and prior acquired dnscat2 SHA256. Stop on a provenance/format blocker;
report what passed and what could not be tested. Commit the verified package;
no push or automatic detector experiment.

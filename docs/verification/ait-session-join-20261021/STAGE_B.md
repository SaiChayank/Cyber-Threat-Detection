# Diagnostic DNS visibility and receiver join freeze

Stage A establishes the named `put` service configuration on `internal_share`,
mapped to 10.143.0.103/UTC, and original successful service lifecycle events at
2022-01-24T13:50:39.298Z. START and STOP have that same timestamp: do not treat
this as an independently measured original exfiltration start. Receiver metadata
independently establishes executed DNSteal data and per-file end markers, but not
the originating client for each receive event or independent experiments.
Producer DNS labels are domain/listener-interval heuristics; do not adopt them as
independent query/session truth. The recorded user state log has application
actions, but lacks DNS question/transaction joins and five-category attribution.

It is justified to test this partial provenance against original DNS questions as
a **development-only source qualification**, not a final evaluation cohort. Freeze
the whole `AIT-LDS-v2.1-russellmitchell` run as exposed development qualification
before any question value access; no train/tuning/reserved roles. All its related
exports, original/derived copies and transfer files share this exclusion. The
other seven AIT testbeds remain unopened and unassigned; related-source independence
would still require review, not automatic reserved eligibility.

Open only `gather/inet-firewall/logs/dnsmasq.log`, 32,228,543 uncompressed bytes,
CRC32 c4cbb523, in the previously whole-checksummed archive. Verify size/CRC before
text analysis, max 32 MiB original bytes. No payload files, label rows, upstream
code, other resolver, receiver traffic JSON, model or detector invocation.

Use original query records only; exclude responses/cache/forwarded messages as
extra client questions. Report all non-query/malformed/unparsed lines. Preserve
source line order/duplicates. Establish actual syntax before freezing a parser.
Report original question types and client source as observed. DNSmasq names are
metadata, no encoded payload decoding. UTC/year reconstruction requires the
original host timezone/simulation metadata; do not invent subsecond precision.

For any file-end-marker check, require the exact literal filename/namespace and
end-marker spelling from the original receiver's metadata plus original query
type and source. Freeze the one-second original-log time bucket match, not a
tunable nearest-neighbour/clock-offset search. Count ambiguous/unmatched events,
source/time disagreements and out-of-window receiver observations separately.
A join is evidence of an observed transfer marker, not complete session truth,
session independence or a precision/recall measurement. No packet count inferred
from receiver events, no constructed session split, no benign complementary label.

If original query metadata cannot demonstrate complete original execution bounds,
required independent/tool/control coverage, keep the final gate BLOCKED. No
reserved values or single reserved pass is used by this diagnostic.

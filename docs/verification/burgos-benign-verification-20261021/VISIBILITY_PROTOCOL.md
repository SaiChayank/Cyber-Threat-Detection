# Stage B visibility freeze — before original packet records

Stage A passed selected-member CRC/size and classic Ethernet PCAP validation.
The original member SHA256 is
`f1b0e48cfdbdd38a7701c99b364ed0bd70521224402a9d96eeac7b0dd9845e57`.
Only that fixed benign-first file may be opened in this stage. Do not open the
second capture, any attack capture's packet records or reserved inputs.

Preregister neutral qualification outputs: exact frame count, captured/wire
length differences, first/last/min/max original timestamps and their declared
encoding, backwards steps/duplicate frames, IP/transport visibility, DNS/53
client-question and response counts, observed QTYPEs, source counts (hashed),
question completeness and actual runtime parser agreement. Keep mDNS/5353 and
LLMNR/5355 separate. Reuse existing transport/wire question helpers and runtime
ProtocolParser; do not decode response RDATA, encrypted payload or applications.
Do not sort, adjust timestamps, deduplicate, replay or call feature/model/rule
code. A zero/missing question count is reported, not forced into a success.

Print/store no original query strings or addresses. Record supplemental hashed
first-label exposures for later exclusion; this is inspected development-source
qualification, not an untouched reserved assignment. Do not infer CDN/telemetry/
TXT/service-discovery/machine-name application labels from the observed strings
or fabricate independent sessions by slicing traffic. The producer's capture-level
benign statement remains distinct from independent per-DNS-session truth.

Pin the visibility implementation and existing parser/helper sources before this
pass. Controlled fixtures may test chronology, DNS responses, service separation,
parser mismatch accounting and truncated records without inspecting this source.
Verify the original file before/after and preserve all 130 protected originals.
No candidate scoring, accuracy metric, training, thresholds or activation. The
full frozen 20/50/category/timing requirements remain unchanged and unassessed.

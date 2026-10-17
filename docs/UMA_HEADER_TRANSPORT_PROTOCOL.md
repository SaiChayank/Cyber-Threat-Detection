# UMA header-only transport with existing dataset tooling

18 October 2026 IST; baseline `5f23a7d`. A separate bounded follow-up to the
previously frozen header-blockage record; do not rewrite that historical evidence.
Local package inspection establishes an already installed `stream_inflate`
`stream_inflate64(chunk_size=4)` decoder used by `stream_unzip` for method 9.
No dependency install, source-data request, capture parser or contract change.

Before values, pin original archive SHA256/size, all 45 central-directory members,
local compressed-data offsets, installed decoder version/source SHA256 and exact
four-byte output bound. Check archive identity before decoder access. Use only
the downloaded UMA original. All source/data/model roles and DNS gates unchanged.

Read ZIP local-file-header metadata only to locate the named unencrypted method-9
member's compressed bytes. Use existing stream_inflate64 with output chunks of
four bytes. Return ONLY the first four decompressed bytes and close the decoder;
at most 1 MiB compressed input per member, no advance to packet blocks or another
member through an unbounded sequential iterator. Never request a password or
decryption; refuse encrypted/mismatched metadata. No member extracted to disk.

If magic is PCAPNG, record unsupported runtime container and stop that member.
Do not decode section/interface/packet blocks, link type, snaplen, packet times,
DNS questions, payloads or model features. Unexpected/truncated magic remains
unverified; do not add a parser or convert captures. No file/session count becomes
an independent DNS label/count. Partial prefix inspection does not verify a full
member CRC or packet validity; whole-original hash anchors publisher bytes only.

Minimal evidence-local diagnostic helper and exact tests may establish output
and compressed-input bounds, identity/encryption refusal and classifier-free
execution. Test fixtures are newly generated archive-transport unit bytes only,
not scored traffic, training or evaluation observations. Production code untouched.

DoD: precise supported/unsupported/unknown four-byte observations, 45 bounded
attempts or explicit failure, tests and protected integrity. No score, training,
candidate activation or new dependency. A successful transport check resolves
only header access, never missing DNS session/category ground truth. Stop after
recording that capability decision; continue only separately eligible tasks.

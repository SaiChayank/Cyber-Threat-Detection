# PCAPNG support

29 October 2026. `ingest/pcapng.py` reads PCAPNG captures through the same
`PcapReader`, offline CLI, flow-export reader, lab harness and upload API
(`.pcap` or `.pcapng`, up to 16 MiB). The file's magic number selects the format.

Supported: both byte orders; repeated sections; Interface Description Blocks with
the `if_tsresol` option (decimal or binary resolution); Enhanced Packet Blocks.
Ignored: name-resolution, statistics and unknown blocks. Simple Packet Blocks carry
no timestamp and are skipped.

Rejected with fixed, analyst-safe messages (HTTP 422 on upload): non-Ethernet
interfaces ('Only Ethernet captures are supported'), a missing or malformed section
header, a block shorter than 12 bytes, not a multiple of 4, larger than 16 MiB, with
mismatched leading and trailing lengths, an unknown interface id, or a captured
length above the original length ('Invalid PCAPNG block'), and files cut off
mid-block ('Truncated PCAPNG block'). Block sizes are validated before any read, so
a hostile file cannot force a large allocation. Input is read-only.

Limits: Simple Packet Blocks are skipped; compressed or encrypted PCAPNG is not
supported; each interface's timestamp offset option (`if_tsoffset`) is ignored.
Tests: `tests/test_pcapng.py`.

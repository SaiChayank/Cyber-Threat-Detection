# Classic Ethernet PCAP upload validation

Run `python -m pytest tests/test_pcap_upload.py -q`. The tests post bytes to the
existing `/api/replay/pcap` endpoint with an isolated SQLite database and track
every temporary upload file. No monitored host is contacted.

| Input / control | Expected API or replay behavior | Result |
|---|---|---|
| Valid classic Ethernet PCAP | Accept, incrementally replay observed packet, complete, delete temp file | Pass |
| Empty upload | HTTP 422, complete-header error, delete temp file | Pass |
| Fake `.pcap` content | HTTP 422, unsupported format, delete temp file | Pass |
| Truncated global header | HTTP 422, delete temp file | Pass |
| Unsupported link type | HTTP 422 (Ethernet only), delete temp file | Pass |
| Invalid packet length | Background replay `failed` with error, delete temp file | Pass |
| Truncated packet body | Background replay `failed` with error, delete temp file | Pass after fix |
| Oversized upload (>16 MiB) | HTTP 413 before writing over limit, delete temp file | Pass |
| Malformed frame beside valid frame | Drop malformed frame, process valid frame, no backend crash | Pass |
| Stop during uploaded replay | Stop before next packet, delete temp file | Pass |
| Path/URL strings or query parameters | Never interpreted as capture sources | Pass |

Only the 24-byte global header is validated before the API returns `running`.
Packet-length and truncated-body errors are discovered during incremental replay
and reported through `replay_status=failed` and `replay_error` in telemetry. A
malformed individual frame is dropped by the existing parser/dead-letter path;
other valid frames continue. Previously, a capture with a truncated packet body
could be reported as `complete`; the upload generator now treats the reader's
truncation count as a replay failure. Temporary upload files are removed after
rejection, completion, failure and stop.

The endpoint accepts uploaded bytes and a bounded speed query only. It has no
server-side path or URL selector; path/URL text is rejected as invalid capture
bytes, and query parameters cannot select a source. Support remains limited to classic
Ethernet PCAP; no archive, remote URL or PCAPNG handling was added. This is a
read-only replay validation, not a claim about arbitrary capture formats or
production upload throughput.

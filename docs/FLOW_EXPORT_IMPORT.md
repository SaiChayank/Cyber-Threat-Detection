# Flow export import

Passive import of NetFlow v5/v9, IPFIX and sFlow v5 records from a capture.
Nothing is sent to exporters. Implementation: `ingest/flow_export.py`.

## What it imports

The input is an Ethernet PCAP (classic version 2.4, linktype 1) or PCAPNG holding the
export datagrams a collector port received. Only UDP packets to these ports
are decoded:

| Protocol | UDP destination ports |
| --- | --- |
| NetFlow v5 / v9 | 2055, 2056, 9025, 9995, 9996 |
| IPFIX | 4739, 4740 |
| sFlow v5 | 6343 |

Datagram version decides the decoder: sFlow when the first word is 5, otherwise
the 16-bit version (5, 9 or 10). Other versions are counted as `unsupported`.

## How to use it

- CLI (prints alerts, writes no analyst history):
  `python -m replay.cli capture.pcap --source flow-export`
- API (upload limit 16 MiB; `source` is `packets` by default):
  `POST /api/replay/pcap?source=flow_export`
- Lab label file, which must name a `.pcap` capture:
  `"source": "flow_export"` (see [lab evaluation](LAB_EVALUATION.md)).

Note the spelling: the CLI option uses a hyphen, while the API and label file
use an underscore.

## Record mapping

Each flow record becomes one `TrafficEvent`:

- **Timestamp:** the flow end time. NetFlow v5 uses header boot time plus the
  last-switched value. NetFlow v9 and IPFIX use end-millisecond or end-second
  fields when present, then uptime-relative fields, and otherwise the export
  time. sFlow samples use the datagram's PCAP arrival time.
- **TCP flags:** `syn` is set when SYN is seen. `syn_packets` is the packet
  count when SYN is set without ACK, `0` when there is no SYN, and unknown
  otherwise. `tcp_fin_rst` is true when FIN or RST is set, and unknown when
  neither is set.
- **Encryption:** port 443 on either side marks the flow `encrypted`; UDP/443
  becomes transport `QUIC`.
- **Reverse bytes:** IPFIX element 1 under enterprise 29305 (RFC 5103
  `octetDeltaCount`) sets `reverse_bytes` and `reverse_observed`. NetFlow
  records never carry reverse bytes.
- **sFlow:** only flow samples (formats 1 and 3) with raw Ethernet header
  records are decoded. `packets` equals the sampling rate and `bytes` equals
  the sampled IP total length times the rate. Counter samples are ignored.
- **Clamps:** packets are capped at 1,000,000 and bytes at 1,000,000,000 per
  record.

Records with no source or destination, or zero packets, are dropped and
counted as `skipped_records`.

## Templates

- Cached per exporter address and observation domain (v9: source ID; IPFIX:
  domain ID), so one exporter cannot use another's templates.
- Keyed by template ID and bounded to 1,024 entries. When full, the oldest
  inserted template is evicted; this is insertion order, not least-recently
  used.
- A template with zero fields removes the cached template. The code applies
  this to both v9 and IPFIX.
- Data sets whose template is not cached are dropped and counted as
  `missing_template`. Templates usually arrive before data, so replay the
  capture from its start.

Malformed datagrams are counted as `malformed` and do not stop the capture.
A truncated PCAP file raises `ValueError`.

## Limits

- Options templates and option records are ignored; they describe the exporter,
  not observed flows.
- sFlow counter samples and non-raw-header sample records are not decoded.
- IPv6 extension headers are not parsed: the next-header value is read
  directly, so flows behind extension headers may be misclassified.
- Fragmented IPv4 packets are dropped.
- No live UDP collector runs. The system is passive and read-only, so input is
  always a capture file.
- v9 and IPFIX flow end times depend on the exporter's uptime and clock. A
  wrong clock shifts the timeline.
- Late or out-of-order records are sorted within one datagram only.

# PCAP Throughput Benchmark

## What is measured

End-to-end throughput from a classic Ethernet PCAP file through the runtime path:
PCAP read, protocol parse, feature extraction and inference. Two passes are timed
over the same generated capture:

- **Parse only:** `PcapReader().read_packets` plus `from_packet`.
- **Full path:** parse plus `Pipeline().process` for every event.

Flows are distinct 5-tuples (source IP, destination IP, source port, destination
port, protocol) seen in the full-path pass.

## How to run

From the repository root:

```
.venv/Scripts/python.exe -m benchmarks.pcap_throughput --packets 50000
```

The report prints to stdout and is written to `benchmarks/pcap_throughput_latest.json`
by default. Use `--output PATH` for a separate destination. `--packets` must be at
least 1000.

Tests: `.venv/Scripts/python.exe -m pytest -q tests/test_pcap_throughput.py`

## Field meanings

- `packets`: packets read back from the capture.
- `packets_per_second`: packets divided by full-path elapsed seconds.
- `flows` and `flows_per_second`: distinct 5-tuples and that count divided by elapsed seconds.
- `sustained_mbps`: wire bytes times 8, divided by elapsed seconds, divided by 1e6.
- `elapsed_seconds`: wall time of the full-path pass only. Capture generation and hashing are excluded.
- `capture_bytes`, `capture_sha256`: size and SHA-256 of the generated file. Same input gives the same hash.
- `capture_duration_seconds`: last timestamp minus first timestamp.
- `realtime_factor`: capture duration divided by full-path elapsed. Values above 1 mean the pipeline keeps up with the capture in real time.
- `parse_only_*`: the same packet, rate and Mbps measures for the parse-only pass.
- `alerts`, `alerts_by_class`: alerts emitted by the full path.
- `hardware`, `python`, `platform`, `workload`, `scope`, `generated_at_utc`: run context.

## Scope and limits

- The capture is synthetic, benign and deterministic (seed 1). It has no floods, scans or attack patterns, so alert counts are a sanity signal, not a detection-accuracy result.
- Single machine, single process, no concurrency. Numbers depend on CPU, Python version and background load.
- Excludes SQLite persistence, HTTP ingest, SSE delivery, browser rendering and any network I/O.
- Packet records and flow records differ. Packets/s counts parsed packets. Flows/s counts distinct 5-tuples in the same capture, which is a different unit.
- Real captures have fragmentation, TCP reassembly needs and more varied traffic. These results do not transfer directly.

## Latest result (29 October 2026, `benchmarks/pcap_throughput_latest.json`)

50,000 benign packets (3,091 flows, 37.4 MB, 5.0 s of capture), Ryzen 7 8845HS:

| Path | Packets/s | Flows/s | Sustained Mbps |
| --- | --- | --- | --- |
| Parse only (reader + adapter) | 81,397 | n/a | 487 |
| Full path (parse + features + inference) | **1,257** | 77.7 | **7.5** |

The full path runs at about 0.1x real time on this packet workload, so it
does **not** sustain 2,000 packets/s. The project's 2,000 events/s gate is
defined on flow-summary metadata events (3,000+ events/s, p95 about 1 ms, see
[Performance validation](PERFORMANCE_VALIDATION.md)); one packet is a much
heavier unit than one summary. Parsing is not the bottleneck.

Profiling found two causes: per-event failure-safe state copies and the
20-feature Gaussian model scoring every event. Copying the flow-ID table and
the new TLS/slow-HTTP state was replaced by a copy-on-write map
(`features/cow_map.py`), which raised the first run (669 packets/s) to the
figure above. The remaining copies (per-source history and byte windows) and
model scoring are the next targets. The workload also raised 2 false
`ENCRYPTED_MALWARE` alerts from the rare-fingerprint rule; tune that in P0-5.
Treat all figures as one-machine, synthetic-capture results.


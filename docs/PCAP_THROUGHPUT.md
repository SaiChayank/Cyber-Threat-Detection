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
| Parse only (reader + adapter) | 67,281 | n/a | 403 |
| Full path (parse + features + inference) | **2,960** | 183.0 | **17.7** |

The full path clears 2,000 packets/s on this workload (about 0.22x real time on
a capture compressed into 5 s). The saved run was quiet (no background load); five earlier runs on the same code under
moderate background load gave 2,126 to 2,240 packets/s, and a slower build ranged 1,745 to
2,155. Expect roughly 2,100 to 3,000 packets/s depending on machine load. The project's separate 2,000 events/s gate on
flow-summary metadata events is unchanged and still passes (3,301 events/s,
p95 0.94 ms, same 1,170 alerts; see [Performance validation](PERFORMANCE_VALIDATION.md)).

## How it got there

The first run measured 669 packets/s. Profiling found that the cost was the
failure-safe staging copying whole state tables on every event, then the
extractor rescanning each source's retained history (up to 512 events in 60 s)
several times per event, which made throughput fall as histories filled
(about 1,300 packets/s over 50,000 packets).

1. `features/cow_map.py`: a copy-on-write LRU map replaces whole-table copies for the
   flow-ID, TLS-session, slow-HTTP/slow-read, per-source history, byte-window
   and SYN/UDP target tables. A failed event is still discarded without side effects.
2. `features/source_history.py`: each source's history keeps a running byte total, the
   10-second window's SYN count and distinct destination/port counts, and a
   per-peer index, instead of rescanning the history on every event.
3. The model's per-class constants are computed once, recent destinations are
   no longer stringified per event, and staged copies of plain objects use a direct
   `__dict__` clone instead of `copy.copy`.

**Results are bit-identical.** A differential run of the previous extractor against the
new one over 20,000 events produced zero differing feature values with the default
bounds, a tiny per-source event limit, a tiny source limit (forcing eviction) and a
90-second gap (forcing expiry). The nine demo traces and the frozen model are
unchanged, so no feature-contract change was needed. `tests/test_source_history.py`
checks the new structures against brute-force scans. The only intended difference
is that tables that were first-in-first-out (flow IDs, TLS, slow-HTTP) now evict the
least recently used entry, which only matters beyond their 4,096-entry bounds.

Remaining limits: throughput still declines slowly as histories fill; the same-peer
timing and size statistics still scan that peer's retained events. The workload used to
raise 2 false `ENCRYPTED_MALWARE` alerts; they came from the synthetic classifier labelling
ordinary port-443 flows (no TLS metadata), not from the TLS rules. A guard now requires
observed TLS or QUIC metadata for a model-only encrypted hit, and the benign workload
raises 0 alerts. Treat all figures as one-machine, synthetic-capture results.

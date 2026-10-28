# Lab capture evaluation harness

Scores the unchanged runtime pipeline against captures you record in your own
isolated lab, using ground-truth labels you supply. It replaces the stopped
public-dataset qualification route as the way to measure detector quality.

The harness is passive: captures and label files are opened read-only, nothing
is sent on a network, no analyst SQLite history is written, and `--out` refuses
to overwrite an input. Each capture runs through a fresh `Pipeline` in file
order, through the same `PcapReader` → `from_packet` path as PCAP upload and
`replay.cli`.

## Run

```powershell
.venv/Scripts/python.exe -m datasets.evaluate_lab path/to/run01.labels.json path/to/run02.labels.json --out lab-report.json
```

`--dns-tunnel-candidate` scores the disabled DNS-tunnel candidate instead of
the default rule; it does not enable the candidate at runtime. The console shows
one table per split plus `all`; the JSON report holds per-episode detail.

## Label file (`ps26145-lab-labels/1`)

One JSON file per capture. Paths are relative to the label file.

```json
{
  "format": "ps26145-lab-labels/1",
  "capture": "run01.pcap",
  "split": "test",
  "episodes": [
    {"id": "syn-1", "label": "DDOS", "scenario": "syn_flood", "tool": "hping3",
     "start": "2026-11-02T10:00:05Z", "end": "2026-11-02T10:00:35Z",
     "hosts": ["192.168.56.20"]},
    {"id": "backup-1", "label": "BENIGN", "scenario": "nightly_backup",
     "start_ms": 1793613700000, "end_ms": 1793613760000,
     "hosts": ["192.168.56.0/24"]}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `capture` | Classic Ethernet `.pcap` (the formats `PcapReader` accepts) or `TrafficEvent` `.jsonl`. |
| `split` | `train`, `validation`, `test` or `unassigned` (default). Tune only on train/validation; score test once. |
| `label` | `BENIGN` or a runtime threat class: `DDOS`, `BOTNET_C2`, `DGA_DOMAINS`, `DNS_TUNNELLING`, `ENCRYPTED_MALWARE`, `RECONNAISSANCE`, `DATA_EXFILTRATION`. |
| `scenario` | Free text used for the per-scenario breakdown; defaults to the label in lower case. |
| `start`/`end` or `start_ms`/`end_ms` | Inclusive window: ISO-8601 with an explicit UTC offset, or epoch milliseconds. |
| `hosts` | IP addresses or CIDR networks. An event belongs to the episode if its source **or** destination is listed. An empty list matches every event in the window. |
| `tool` | Optional note of the generator used. |

Events matching no episode are benign background. Label legitimate look-alikes
(backups, health checks, authorised scanners) as `BENIGN` episodes so their
false alerts are reported separately. If episodes overlap, the first listed one
wins and the event is counted in `ambiguous_events`; fix overlaps before
trusting the numbers.

## Metrics

- **Episode recall:** a threat episode is detected once any of its events
  triggers an alert of its labelled class.
- **Time to detect:** first correct alert minus the episode's first observed
  event (event time, not wall-clock); `events_into_episode` shows it fired while
  streaming.
- **Alert precision:** alerts of a class on episodes of that class, divided by
  all alerts of that class.
- **Benign false alerts:** alerts on background and `BENIGN` episodes, with a
  rate per 1,000 benign events and the count of labelled benign episodes that
  raised any alert.
- **Ingest health:** late (out-of-order) events dropped by the extractor and
  parser corrupt/truncated/unsupported packet counts.

The report records SHA-256 of every capture and label file plus the runtime
model, so a result can be tied to exact inputs. Results are only as reliable
as the labels: they measure this pipeline on your lab traffic, not field
accuracy.

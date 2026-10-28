# Lab capture protocol

Checklist for recording labelled captures in your own isolated lab so that
`python -m datasets.evaluate_lab` can score the detectors. Label format and
metrics: [Lab evaluation harness](LAB_EVALUATION.md). Flow exports:
[Flow export import](FLOW_EXPORT_IMPORT.md).

## 1. Ground rules

- Isolated lab only: every VM, switch and attacker is yours. No real networks,
  no third-party targets, no internet egress during a run.
- Passive capture: the capture host listens on a mirror/tap port and sends
  nothing (no DNS lookups, updates or management traffic while recording).
- Format: classic Ethernet `.pcap`, not pcapng. Use snaplen 65535 so DNS and
  TLS handshakes are complete.
- One run = one `.pcap` + one `.labels.json`. Never merge runs or split a run.
- Clocks: sync every host and the capture host with NTP before the session.
  Record the offset (`chronyc tracking` or `w32tm /query /status`) in your lab
  notes. Write label times in UTC with an explicit `Z` offset.
- Keep the raw capture unmodified. Do not edit `.pcap` files after recording.

## 2. Lab setup

Minimal topology:

- Client VMs (benign users, optional infected host)
- Server VM (web service, DNS resolver, flow exporter if testing `flow_export`)
- Attacker VM (hping3, Slowloris, dnscat2/iodine, DGA or C2 emulator)
- Capture host attached to a mirror (SPAN) port that sees all of the above

Capture command on the capture host (replace the interface name):

```sh
tcpdump -i <iface> -s 65535 -n -w run01.pcap
```

Start capture at least 30 s before the first scenario and stop at least 30 s
after the last one, so the window has clean edges. Note the start and stop
times in the lab log.

For flow-export evidence, capture the export datagrams that reach the
collector port (for example UDP 2055, 4739 or 6343), not the flows themselves.
Name the label file's `capture` as the `.pcap` and set `"source": "flow_export"`.
Replay from the start of the capture, because templates usually arrive first.

## 3. Scenario checklist

Generate traffic only against lab VMs you own. Record the tool, its version,
the seed and the intensity in the label's `tool` field where it fits.

| Label | Tool named in the problem statement | Scenario name | Record | `hosts` |
| --- | --- | --- | --- | --- |
| `DDOS` (SYN flood) | hping3 SYN | `syn_flood` | Sustain >=60 s; vary rate (low and high) and seed | victim IP |
| `DDOS` (UDP flood) | hping3 UDP | `udp_flood` | Sustain >=60 s; vary packet size and rate | victim IP |
| `DDOS` (slow HTTP) | Slowloris | `slow_http` | Hold >=50 connections to one service for >=120 s; detector needs open >=30 s at <=100 B/s | victim web IP |
| `BOTNET_C2` | Sandboxed C2 emulator | `c2_beacon` | >=10 min; vary interval and jitter | infected client + C2 IP |
| `DGA_DOMAINS` | Published DGA algorithm samples (DGArchive or equivalent) | `dga_domains` | Replay DGA lookups from one client; include NXDOMAIN answers | client IP + resolver IP |
| `DNS_TUNNELLING` | dnscat2 or iodine | `dns_tunnel` | Tunnel session >=60 s; record both directions | client IP + authoritative server IP |
| `ENCRYPTED_MALWARE` | Sandboxed C2 emulator over TLS | `encrypted_c2` | >=10 min of small, regular TLS sessions | infected client + C2 IP |
| `RECONNAISSANCE` | Not named in the problem statement; use a lab scanner you choose | `recon_scan` | Record scanner, version and scan type in `tool` | scanner IP |
| `DATA_EXFILTRATION` | Not named in the problem statement; use a lab transfer you choose | `exfil_upload` | Record the transfer method and volume in `tool` | client IP + sink IP |

Notes:

- Vary intensity, tool and seed across runs. A single setting per threat will
  not show generalisation.
- For `ENCRYPTED_MALWARE`, you may add the lab family's JA3, JA3S or JA4 to
  `detection/tls_indicators.json` with a provenance note (format: [encrypted-session detection](ENCRYPTED_SESSION_DETECTION.md)). The run that produced the
  fingerprint must then not be scored as test data.
- Stop each run cleanly: close tunnels, stop floods, and let idle connections
  time out for at least 120 s if you need the slow-HTTP state to clear.

## 4. Hard benign look-alikes

Label these `BENIGN` so false alerts are reported separately.

| Look-alike | Scenario name | Generator | Why it looks like a threat | `hosts` |
| --- | --- | --- | --- | --- |
| Bulk transfer | `iperf3_bulk` | iperf3, Ostinato or TRex | High volume, sustained | client + server IPs |
| Nightly backup | `nightly_backup` | rsync or similar | Large, long-lived transfer | backup client + target |
| Health checks and API polling | `health_poll` | Scripted HTTP client | Periodic, regular, like beaconing | monitor + service IPs |
| Authorised scan or inventory | `auth_inventory` | Lab-only scanner | Many probes, like recon | scanner + lab IPs |
| Normal browsing | `browse_parallel` | Browser or scripted client | Many parallel connections | client IP |
| CDN or video | `video_stream` | Scripted or browser client | Large, steady downloads | client IP |
| Long-poll and keep-alive | `long_poll` | Scripted client | Many quiet connections, like slow HTTP | client + service IPs |
| Ordinary DNS and TLS | `app_dns_tls` | Lab app traffic | Small, regular sessions, like tunnels or C2 | client + server IPs |
| Large legitimate upload | `bulk_upload` | Scripted client | Large outbound transfer, like exfiltration | client + sink IPs |

Benign runs need at least 3 captures per category (section 6).

## 5. Labelling procedure

1. Note each scenario's start and stop from your lab log, in UTC.
2. Widen each window by a few seconds (for example 5 s before, 5 s after) so
   the first and last packets are inside it.
3. Copy the format from [LAB_EVALUATION.md](LAB_EVALUATION.md) and set
   `"capture"` to the `.pcap` name in the same folder.
4. Give each episode a unique `id`, a valid `label`, a `scenario` name from
   section 3 or 4, and a `tool` note.
5. Fill `hosts` with the IPs or CIDRs from section 3 or 4. Use an empty list
   only when the window has no other traffic.
6. Avoid overlapping episodes in one file. The first listed episode wins and
   the overlap is counted as `ambiguous_events`. Split time or host ranges so
   each event matches one episode.
7. Add `"source": "flow_export"` only for flow-export captures.
8. Set `"split"` (section 6) and check the file loads with the harness before
   the long run.

Example:

```json
{
  "format": "ps26145-lab-labels/1",
  "capture": "run01.pcap",
  "split": "train",
  "episodes": [
    {"id": "syn-1", "label": "DDOS", "scenario": "syn_flood", "tool": "hping3 2.0.x seed 11",
     "start": "2026-11-02T10:00:05Z", "end": "2026-11-02T10:01:35Z",
     "hosts": ["192.168.56.20"]},
    {"id": "backup-1", "label": "BENIGN", "scenario": "nightly_backup", "tool": "rsync",
     "start": "2026-11-02T10:05:00Z", "end": "2026-11-02T10:06:00Z",
     "hosts": ["192.168.56.30", "192.168.56.20"]}
  ]
}
```

## 6. Splits and counts

- Minimum: at least 6 runs per threat class, with a mix of intensities, tools
  and seeds. At least 3 runs per benign category.
- Split by whole run about 50/25/25 into `train`, `validation` and `test`.
  Never split one run across splits.
- Tune thresholds only on `train` and `validation`.
- Score `test` once, at the end. Do not re-run it after changing a threshold.
- Record the split decision before you look at results.

## 7. Running and reading the harness

From the repo root (Windows):

```powershell
.venv/Scripts/python.exe -m datasets.evaluate_lab path/to/run01.labels.json path/to/run02.labels.json --out lab-report.json
```

Add `--dns-tunnel-candidate` only to score the disabled DNS-tunnel candidate.
The `--out` file must not already exist as an input.

Numbers that matter:

- **Episode recall** per class: share of threat episodes with a correct alert.
- **Alert precision** per class: correct alerts divided by all alerts of that class.
- **Benign false alerts** per 1,000 benign events, and the number of labelled
  benign episodes that raised any alert.
- **Time to detect**: first correct alert minus the episode's first event.
- **Ingest health**: late events dropped and corrupt or unsupported packets.

When asking Claude to tune, send the `lab-report.json` (the `--out` file) and
the label files (without the `.pcap` files, which can be large). Include the
run IDs and scenario names for any misses or false alerts.

## 8. Safety and ethics

- Generate attack traffic only against machines you own, inside an isolated
  network with no route to anything else.
- Do not reuse lab captures' IPs, domains or payloads outside the lab.
- Remove or disable any tool that can reach the internet before a run.
- Keep the capture host passive. If you are unsure whether a run leaked
  traffic outside the lab, discard it and record why.

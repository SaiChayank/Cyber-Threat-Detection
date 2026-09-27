# PS26145 — Isolated Synthetic Traffic-Generation Lab Architecture
**Scope:** Design of the traffic-generation/capture environment only — this is the environment that *produces* the passively-observed data described in earlier tasks. No attack-generation code, no detection pipeline, no feature engineering here. This lab sits entirely upstream of the detector; the detector's streaming ingestion design is a separate, later task.

Safety principle applied throughout: **nothing in this lab ever targets, resolves against, or communicates with a real external system.** Every generator, victim, and C2/tunnel endpoint lives inside the isolated segment.

---

## 1. Network Topology

Two logically and physically/virtually separate segments, connected only through the monitoring host in a one-way (diode-like) fashion:

```
                    ┌─────────────────────────────────────────────┐
                    │        ISOLATED LAB SEGMENT (no egress)       │
                    │        Private range, e.g. 10.99.0.0/24       │
                    │        No default gateway to internet         │
                    │                                                │
   ┌────────────┐   │   ┌────────────┐   ┌───────────────┐         │
   │  Benign    │───┼──▶│  L2 Switch │◀──│    Attack      │         │
   │  Traffic   │   │   │  (mirrored │   │   Simulator    │         │
   │ Generator  │   │   │   port)    │   └───────────────┘         │
   │  VM(s)     │   │   └─────┬──────┘                              │
   └────────────┘   │         │              ┌───────────────┐     │
                    │         ├─────────────▶│   Victim /     │     │
                    │         │              │   Service VM   │     │
                    │         │              │ (web/DNS/TCP)  │     │
                    │         │              └───────────────┘     │
                    │         │                                     │
                    │    (SPAN/mirror copy — one direction only)    │
                    └─────────┼───────────────────────────────────┘
                              ▼
                    ┌───────────────────────┐
                    │  Passive Monitoring    │      No IP on this NIC.
                    │  Interface (tap NIC,   │      Promiscuous mode only.
                    │  no IP, no route back) │      Cannot originate traffic
                    └──────────┬────────────┘      onto the lab segment.
                               │
                    ┌──────────▼────────────┐
                    │   Capture System       │  Writes raw pcap only.
                    │  (tcpdump/dumpcap)     │
                    └──────────┬────────────┘
                               │ (files copied out via
                               │  separate mgmt NIC, batch)
                    ┌──────────▼────────────┐
                    │  MANAGEMENT / CONTROL  │  Separate virtual network.
                    │  SEGMENT (out-of-band) │  Orchestration, NTP, logging,
                    │  e.g. 10.99.100.0/24   │  flow extraction, ground-truth
                    │                        │  logger, storage.
                    └────────────────────────┘
```

**Key isolation properties:**
- The isolated lab segment has **no default gateway, no NAT rule, and no DNS forwarding to the real internet.** All private IPv4 space (RFC 1918), single subnet, single L2 domain (or a small set of VLANs if multiple attack sources are needed for fan-out scenarios).
- The **monitoring interface is unbound** — no IP address assigned, interface set to promiscuous/monitor mode only. This is the practical, virtualized equivalent of a hardware data diode: it can receive a mirrored copy of every frame on the lab segment but has no protocol stack that could originate a reply, exactly mirroring the PS's "no physical or protocol-level path back" architecture.
- All orchestration (starting/stopping tools, collecting logs, NTP sync, file export) happens over a **second, separate management network**, never over the monitored segment itself — this prevents orchestration traffic from contaminating the captured dataset and keeps the capture path genuinely passive-only.

---

## 2. VM / Container Responsibilities

| Component | Role | Contains |
|---|---|---|
| **Benign Traffic Generator** | Produces "normal" background load | iperf3, Ostinato, TRex (per earlier dataset-portfolio decision); optionally a lightweight internal HTTP/HTTPS client hitting the victim's web service for protocol diversity |
| **Attack Simulator** | Produces all seven threat behaviors (one VM/container per tool, or one VM with all tools installed — a scaling decision, not fixed here) | hping3, Slowloris, dnscat2, iodine, DGA-domain query script, sandboxed C2 client, port-scanning tool, exfiltration-transfer script |
| **Victim / Service System** | The target that receives both benign and attack traffic | A minimal internal web server (self-signed TLS), an internal DNS resolver (authoritative only for lab-owned fake zones — see §7), a generic TCP/UDP echo/listener service, and (for exfiltration/C2 scenarios) a "compromised-emulated" host role |
| **C2/Tunnel Endpoint (attacker-side)** | Plays the "attacker infrastructure" role for C2 and DNS-tunnelling scenarios — kept entirely inside the lab | Sandboxed C2 server component, dnscat2/iodine server component |
| **Passive Monitoring Host** | Captures a mirrored copy of all lab-segment traffic | Tap/mirror NIC (no IP), `tcpdump`/`dumpcap`, local disk buffer for raw pcap before batch export |
| **Orchestration/Control Host** | Drives experiments, is the single source of scenario timing truth | Scenario scheduler/script runner, ground-truth logger, internal NTP server, experiment manifest writer |
| **Flow Extraction Host** (can be same as control host) | Offline, batch conversion of captured pcap into flow records | nfstream / CICFlowMeter-equivalent, reading only from the exported pcap archive — never touches the live lab segment |
| **Storage** | Holds raw captures, flow records, labels, metadata | Structured directory tree or object store, see §9 |

Each VM/container is single-purpose so that a failure or misconfiguration in one (e.g., the attack simulator) cannot alter another's behavior — and so ground-truth attribution of "which box did what" stays unambiguous per experiment.

---

## 3. How Passive Capture Works

1. The L2 switch (physical managed switch, or virtual switch such as Open vSwitch / VMware vSwitch / Linux bridge) is configured with a **mirror/SPAN port** that receives a copy of all frames traversing the benign-generator ↔ victim and attack-simulator ↔ victim links.
2. The monitoring host's NIC is connected only to this mirror port. It is placed in **promiscuous mode** and, critically, is given **no IP address and no routing configuration** — it is a listen-only interface at the OS level, so even a compromised or misbehaving capture process cannot inject traffic back onto the lab segment through it.
3. `tcpdump`/`dumpcap` on the monitoring host writes raw packets to local rotating pcap files, tagged with a monotonically increasing sequence and wall-clock timestamp per file.
4. Captured pcap files are periodically (batch, not live-streamed at this stage) copied off the monitoring host to the storage system **via the separate management NIC**, which is a distinct physical/virtual interface from the mirror-only capture NIC — this keeps the "read-only observation" property intact even during export, since the mirror NIC itself never participates in the file-transfer conversation.
5. Flow extraction (nfstream/CICFlowMeter-equivalent) runs later, offline, against the exported pcap archive on the flow-extraction host — this is explicitly **not** part of the live capture path, and is a batch step for building the training/eval dataset described in the earlier dataset-portfolio task. (The PS's *streaming* detection requirement applies to the eventual detection pipeline, not to this data-generation lab — that pipeline design is a separate later task.)

This structure is a faithful, safe emulation of the PS's real-world unidirectional data-diode architecture: the monitor sees everything, can prove it never had a return path (no IP, no route), and all "production network" traffic stays confined to the isolated segment.

---

## 4. Experiment IDs

Format: `EXP-<YYYYMMDD>-<THREAT_CODE>-<TOOL>-<SEQ>`

- `THREAT_CODE`: one of `DDOS`, `C2BEACON`, `DGA`, `DNSTUN`, `TLSMAL`, `RECON`, `EXFIL`, or `BENIGN` for pure background-only runs.
- `TOOL`: short tag for the specific generator used (e.g., `HPING3`, `DNSCAT2`, `IODINE`, `SLOWLORIS`).
- `SEQ`: zero-padded run counter within that day/threat/tool combination, to allow repeated runs at different intensities.

Example: `EXP-20260915-DDOS-HPING3-003` — the third hping3-based DDoS run captured on 15 Sep 2026.

Every artifact produced by a run (pcap files, flow CSVs, label file, metadata manifest) is named or namespaced under this same experiment ID so all pieces trace back to one unambiguous run.

---

## 5. Timestamps

- **Clock synchronization:** An internal NTP server runs on the management/control segment (not the monitored lab segment, to avoid NTP traffic itself polluting the capture). Every VM — generators, victim, monitoring host, orchestration host — syncs to this internal NTP source before each experiment run, so all clocks agree to sub-second precision.
- **Two timestamp sources are recorded per experiment, deliberately kept distinct:**
  1. **Capture-level timestamps** — the pcap-native timestamp on every captured packet (from the monitoring host's clock).
  2. **Orchestration-level ground-truth timestamps** — the exact start/stop time the orchestration host issued the "begin attack" / "end attack" command to the attack-simulator VM, logged independently by the ground-truth logger.
- All stored timestamps use **UTC, ISO 8601** format, to avoid timezone ambiguity across VMs.
- The deliberate separation between capture-observed timestamps and orchestration-issued timestamps allows later validation that the "attack window" inferred purely from passive observation lines up with the true, independently-logged ground truth — this is itself a useful data-quality check, not just bookkeeping.

---

## 6. Labels

Labels are assigned **only by the orchestration/ground-truth logger**, never inferred from the captured traffic itself (to avoid circular/self-fulfilling labeling).

Per-experiment label record includes:
- `experiment_id`
- `threat_class` — one of the seven official categories, or `benign`
- `tool_used` and tool version/parameters (e.g., hping3 flood rate, dnscat2 encoding mode)
- `attack_window_start` / `attack_window_end` (UTC, from the orchestration log, per §5)
- `source_identity` — which lab VM/container actually generated the traffic (for later leakage auditing — see below)
- `victim_identity` — which lab VM/container was targeted
- `concurrent_benign_profile` — what benign background generators (if any) were running simultaneously, since realistic scenarios mix attack traffic with ongoing benign load
- `confidence` — fixed at `1.0` for all lab-generated ground truth, since it is fully controlled (distinguishing it from any future analyst-provided or model-inferred confidence scores downstream)

At the **flow level**, once flow extraction runs, each extracted flow is joined against the label record by matching its timestamp against the relevant experiment's attack window and source/destination identities — flows falling inside a window and matching the attacker/victim pair get the corresponding threat label; everything else in that capture is `benign`.

---

## 7. Scenario Metadata

Each experiment produces a single metadata manifest (e.g., YAML or JSON) capturing everything needed to reproduce or audit the run:

```yaml
experiment_id: EXP-20260915-DGA-QUERYGEN-001
date: 2026-09-15
threat_class: dga_domains
tool:
  name: internal-dga-query-script
  domain_source: DGArchive-derived-list
  algorithm_family: <recorded per run>
victim:
  host_id: victim-vm-01
  service: internal-dns-resolver
benign_background:
  active: true
  generators: [iperf3-vm-01]
network:
  lab_segment: 10.99.0.0/24
  vlan: none
operator: <who ran it>
notes: <free text — anything unusual about this run>
```

The metadata manifest is what makes each dataset row auditable months later — critical for defending dataset choices during evaluation/judging, and for catching the kind of look-ahead or cross-contamination leakage flagged in earlier data-quality analysis.

---

## 8. Ground-Truth Logger

- Runs on the **orchestration/control host**, entirely off the monitored lab segment.
- Responsible for: issuing start/stop commands to generator and attack VMs, recording the exact orchestration-level timestamps (§5), writing the label record (§6) and metadata manifest (§7) for every experiment, and assigning the experiment ID (§4).
- Because it lives on the out-of-band management network, its own log-writing activity is never visible to or mixed with the mirrored/captured lab traffic — keeping ground truth uncontaminated by the very data it's labeling.
- Acts as the single source of truth that flow-extraction and later model-training steps join against; no other component is allowed to independently assert a label.

---

## 9. Storage Structure

```
/lab-data/
├── raw_pcap/
│   └── <experiment_id>/
│       └── capture_<seq>.pcap
├── flows/
│   └── <experiment_id>/
│       └── flows.csv
├── labels/
│   └── <experiment_id>/
│       └── ground_truth.json
├── metadata/
│   └── <experiment_id>.yaml
└── index/
    └── experiment_manifest.csv   # one row per experiment_id,
                                    # linking all four artifact paths above
```

- Raw pcap is kept as the immutable source of truth; flow extraction can always be re-run against it if the feature-extraction approach changes later (a benefit of not discarding raw captures once flows are derived).
- The central `experiment_manifest.csv` (or a lightweight database, if preferred later) is what a training pipeline actually queries to assemble a dataset split — it never needs to re-scan the raw folders directly.
- This structure directly supports the earlier data-quality requirement to check temporal ordering and deduplication before any train/test split, since every artifact is traceable back to one experiment ID with known start/end times.

---

## 10. How Each SIH Threat Is Safely Represented / Replayed

| Threat | Safe lab representation |
|---|---|
| **SYN/UDP/spoofed-source DDoS** | hping3 runs from the attack-simulator VM against the victim VM, entirely within the isolated subnet. Spoofed source addresses are drawn only from the lab's own private range (e.g., unused addresses within 10.99.0.0/24) — since the segment has no route to the real internet, spoofed packets can never cause backscatter against real hosts. Multiple attack-simulator instances can be added to emulate distributed sourcing without ever leaving the lab. |
| **Botnet C2 Beaconing** | Both the C2 "client" (on the victim/emulated-compromised host) and the C2 "server" (on the dedicated C2/tunnel endpoint role, §2) live inside the lab. The beacon channel never resolves or connects to any real internet address — the emulator's configured destination is always a lab-internal IP. |
| **DGA Domains** | An internal, lab-authoritative fake DNS resolver (part of the victim/service role) is configured to answer only for lab-owned fake zones. Domain-generation algorithms are run offline to produce candidate name lists (from DGArchive or published algorithms, per the dataset-portfolio decision); these names are then queried *against the internal resolver only* — some resolving (to simulate a live C2 domain), most returning NXDOMAIN (to simulate the "trying many candidates" pattern) — without a single real query ever leaving the lab or touching real root/TLD servers. |
| **DNS Tunnelling** | The dnscat2/iodine *server* component runs on the lab's C2/tunnel endpoint role; the *client* runs on the attack-simulator VM. All tunnel traffic transits only the internal DNS resolver chain inside the lab — no real external tunnel endpoint is ever contacted, satisfying both the isolation requirement and the PS's own framing of this as a self-contained detection problem. |
| **Malware Inside Encrypted Sessions** | Benign TLS sessions are generated against the victim's internal HTTPS service using a self-signed certificate (no real CA, no real internet destination). Malicious-emulated TLS sessions are generated by a controlled client on the attack-simulator VM configured to reproduce known malware JA3/JA4 fingerprint characteristics and representative packet-size/timing sequences, connecting only to an internal "malicious-looking" service — no real malware binary or real internet C2 infrastructure is used. |
| **Reconnaissance / Port Scanning** | The scanning tool runs from the attack-simulator VM against the victim VM's port range, entirely within the isolated subnet — never against any real external IP block, sidestepping any legal/ethical concern about unauthorized scanning of real infrastructure. |
| **Data Exfiltration** | A "compromised-emulated" role (a mode of the victim VM, or a dedicated small VM) initiates a large, asymmetric outbound transfer toward the C2/tunnel endpoint role acting as the "attacker-controlled" receiver — both endpoints are inside the lab, so no data ever actually leaves the isolated environment or touches real cloud storage/exfil infrastructure. |

**Cross-cutting safety notes:**
- No component in this lab is ever given a default gateway or DNS forwarder pointing outside the isolated segment — this alone prevents nearly all accidental external contact.
- The only DNS the lab resolves is its own fake, lab-owned zone data — real DGA-generated domain strings are queried against this fake resolver, never the real internet, so no live (potentially actually-malicious) infrastructure is ever contacted.
- All "attacker" roles (C2 server, tunnel server, exfiltration receiver) are lab-internal VMs the team controls, never real internet services — nothing in this design depends on reaching out to any live, real-world malicious infrastructure.

---

**No attack-generation code has been written in this document** — this is environment/architecture design only, per the agreed task scope. Actual tool invocation scripts, DGA query-generation scripts, and the C2 emulator's specific implementation remain open, later work.

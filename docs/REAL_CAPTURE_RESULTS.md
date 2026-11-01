# First measurement on real public captures (P0-5, partial)

29 October 2026. These are the project's first results on real packet captures. They
cover **botnet C2 beaconing, DNS tunnelling and benign traffic only**; every other detector
remains unmeasured on real traffic. Evidence: `docs/verification/ctu13-lab-20261029/` (C2) and
`docs/verification/dns-real-captures-20261029/` (DNS, second section below).

## Data

Two public files from the Czech Technical University CTU-13 collection (no registration
form), downloaded 29 October 2026 into the git-ignored `data/raw/ctu13-lab/`:

| File | Bytes | SHA-256 | Content |
| --- | --- | --- | --- |
| `botnet-capture-20110810-neris.pcap` (Botnet-42) | 58,266,506 | `b89cd593...a6576a36` | Infected Windows VM interface, Neris botnet, 4.75 h, 322,248 parsed events; infected host 147.32.84.165 (heavy DNS, SMTP spam, C2-style ports) |
| `normal-capture-20110817.pcap` (Botnet-50) | 2,581,467 | `476c2d76...3167ee35` | Normal campus traffic (RDP, SMB, web), 1.8 h, 17,125 parsed events |

Full hashes are in `capture-sha256.txt`. Both parse with 0 corrupt packets. Labels are in
`data/lab/ctu13/` (harness format `ps26145-lab-labels/1`): the whole botnet recording is one
`BOTNET_C2` episode on the infected host; the normal recording is one `BENIGN` episode.
`datasets/slice_capture.py` cut each recording into three equal time slices, assigned in time
order to `train`, `validation` and `test`.

## Results

| Step | Data | BOTNET_C2 episode recall | Benign false alerts / 1,000 events |
| --- | --- | --- | --- |
| Baseline, full recordings | both | 1/1, but first alert ~4.75 h in (the very end) | 0.53 |
| Baseline, train + validation slices | 2 + 2 slices | **0/2** | 0.66 |
| Sweep of 16 C2 threshold combinations | train + validation | best 2/2 at 0.82 | cap 1.0 |
| **Tuned defaults, test slices (run once)** | final third of each | **1/1**; 10 of 11 C2 alerts correct (precision 0.91) | **0.20** |

Chosen change: `C2_MAX_IAT_CV` 0.05 -> **0.3** (`detection/rule_thresholds.py`); history 8 and
mean inter-arrival 1 s unchanged. 0.5 scored higher precision but changes four of the nine
frozen demo traces, so 0.3 was taken: the loosest limit that leaves the demo identical
(demo identical up to 0.3, changed from 0.35). The test slices were scored once after the
setting was fixed. The test run's first correct alert came about 74 minutes into a 95-minute
slice, so detection is **late**: Neris is only roughly regular, and the rule needs 8
same-peer events plus a low variation.

## What these results do not show

- One botnet family (Neris), one infected host, one recording. Time slices of a single
  recording share the same malware and hosts, so they are **not independent runs**: this is
  development evidence, not proof the setting generalises to other bots.
- The sweep used both train and validation slices, so there was no separate confirmation
  split before the test run; the test slice is the only held-out evidence.
- Labels are coarse (whole recording on one host). Reconnaissance (182 alerts in the test
  slice), DDoS (3) and DGA alerts raised during the botnet episode are **unverified, not
  proven false**: Neris sprays SMTP to many hosts, which looks like fan-out. They are
  counted as alerts of other classes and were not tuned.
- Nothing here measures DDoS floods, slow-HTTP/slow-read, exfiltration, DNS tunnelling,
  DGA or encrypted malware on real traffic. Those need further public or lab captures.
- Captures are from 2011, from the infected VM's interface only; modern C2 over TLS looks
  different.

## Reproduce

```powershell
.venv/Scripts/python.exe -m datasets.slice_capture data/raw/ctu13-lab/botnet-capture-20110810-neris.pcap data/raw/ctu13-lab/slices --parts 3
.venv/Scripts/python.exe -m datasets.evaluate_lab data/lab/ctu13/*.train.labels.json data/lab/ctu13/*.validation.labels.json
.venv/Scripts/python.exe -m datasets.tune_lab data/lab/ctu13/grid_c2.json data/lab/ctu13/*.train.labels.json data/lab/ctu13/*.validation.labels.json
.venv/Scripts/python.exe -m datasets.evaluate_lab data/lab/ctu13/*.test.labels.json   # once, after fixing settings
```

Captures come from https://mcfp.felk.cvut.cz/publicDatasets/ (CTU-Malware-Capture-Botnet-42 and
-50); cite the CTU-13 dataset (Garcia et al., "An empirical comparison of botnet detection
methods", Computers & Security, 2014) when reusing them.

---

# Second measurement: DNS tunnelling on real captures

Used only captures already on disk (no new download). Labels: `data/lab/dns/`. Evidence:
`docs/verification/dns-real-captures-20261029/` (reports, SHA-256 of the four captures, and the
C2 limit comparison).

## Which captures are valid

| Capture | Snap length | Used as | Why |
| --- | --- | --- | --- |
| `dnscat2_dns_tunneling_1hr.pcap` (public dnscat2, client 10.20.57.3) | 262,144 | **Positive**: DNS tunnelling, 1 h, 7,245 questions, names up to 72 characters, TXT/MX/CNAME | Full-length packets |
| `benign_first_cap.pcap` (Burgos) | 262,144 | Benign | Full-length, 72 ordinary questions |
| CIC DNS 2021 `benign_1`, `benign_2` | **96** | Benign (with caveat) | 83,999 questions from one client to 8.8.8.8; names cut at about 36 characters |
| CIC DNS 2021 `light_*` and `heavy_*` (12 "attack" files) | **96** | **Not used as positives** | Names are truncated at about 34 characters (98-223 questions per file), so tunnelling evidence (long labels) is physically absent; the documents already warned this cannot be repaired by tuning |

## Results (evaluation only; no thresholds changed)

| Detector | Result on the real dnscat2 tunnel | Benign false alerts |
| --- | --- | --- |
| **Default rule** (long first label + TXT/NULL) | **Detected (1/1)**, first alert 1.9 s into the capture; **125 alerts, all on the tunnel (precision 1.00)** | **0 DNS-tunnelling false alerts in 236,845 benign events** |
| Disabled causal candidate (`--dns-tunnel-candidate`) | **Not detected (0/1)** | n/a; stays disabled |

Other classes on the same captures, counted as alerts with no ground truth for them: on benign
traffic, 47 false alerts in 236,845 events (0.198 per 1,000): C2 15, DGA 25, reconnaissance 4,
DDoS 3. Inside the tunnel episode, DGA (241) and reconnaissance (118) alerts fired: dnscat2 names look
random and the client fans out to its resolvers; these are unverified, not counted as wrong.

C2 false alerts, compared with the tuned limit: at the old limit (0.05) the benign DNS already
produced 13 false C2 alerts (12 from `benign_1`, one client polling one resolver at a regular rate);
at the tuned 0.3 it is 15 (two extra, from the Burgos capture). So the first measurement's tuning
added two false alerts over 236,845 benign events; the rest pre-date it (`c2-false-alerts-vs-limit.txt`).

## What this does and does not show

- **Positive:** the shipped default tunnelling rule works on a real tool capture with no false
  alerts on 236,845 benign events, and the disabled candidate does not beat it (it detects nothing
  here), which supports leaving the candidate off.
- **Not a gate result:** the frozen DNS protocol needs at least 20 positive and 50 benign independent
  sessions; this has one tunnel run (one client, one tool, one hour). It is an evaluation, not a
  tuned and independently tested result. No threshold was changed.
- **Truncation:** the CIC captures cannot test tunnelling at all and weaken their own benign role:
  DGA false alerts on truncated benign names (25) may differ on full-length names.
- **Still unmeasured on real traffic:** DDoS floods, slow-HTTP/slow-read, exfiltration, DGA
  recall and encrypted malware.

## Reproduce

```powershell
.venv/Scripts/python.exe -m datasets.evaluate_lab data/lab/dns/*.labels.json
.venv/Scripts/python.exe -m datasets.evaluate_lab data/lab/dns/*.labels.json --dns-tunnel-candidate
```

---

# Third step: false-positive fixes found on real benign traffic (30 October 2026)

Diagnosing the benign false alerts from the first two measurements showed each was a clear
class with a principled guard, not a threshold problem. Every guard has a regression test
(`tests/test_c2_unicast_guard.py`, `test_dga_punycode_guard.py`, `test_ddos_recon_guards.py`),
leaves the nine frozen demo traces identical, and was re-measured on all real captures
(evidence: `docs/verification/real-captures-after-guards-20261030/`).

| False-positive class (real cause) | Guard | Benign alerts before -> after (236,845 DNS events) |
| --- | --- | --- |
| C2 on multicast name lookups (LLMNR 224.0.0.252, mDNS 224.0.0.251): synthetic model and, at the tuned limit, the rule | A C2 peer must be a unicast host: multicast/broadcast destinations never raise C2 | 15 -> 0 |
| DGA on internationalized domain names (`xn--80aalwclyias7g0b.xn--p1ai`): punycode is an encoding | A first label starting `xn--` is never a DGA signal | DGA 25 -> 14 |
| Model-only DDoS on low-rate ICMP (23-98 packets/s) | The synthetic model alone cannot raise a flood alert for protocols other than TCP/UDP unless the rate rule holds | 3 -> 0 |
| Reconnaissance from a resolver's replies to many client ports, and from multicast LLMNR | Scans come from ephemeral ports and target unicast hosts: replies from a service port (<1024, no SYN) and multicast/broadcast targets are not scans | 4 -> 2 |

Overall benign false alerts on the real DNS captures fell from **47 to 16** (0.198 -> **0.068 per 1,000
events**). DNS tunnelling is unchanged: 1/1 detected, 125 alerts all correct, 0 false. The held-out
CTU-13 Neris test slice is unchanged (1/1, 10 of 11 C2 alerts correct); its train+validation benign false
alerts fell from 0.82 to 0.74 per 1,000.

**Remaining known false alerts (not fixed, by design or not fixable here):** 14 DGA alerts on real long
domains made of concatenated words (for example `youtubethumbnaildownloader.com`), the known hard case
for lexical DGA detection; 2 reconnaissance alerts, including a browser contacting 20 CDN hosts in 10 s
(browsing and scanning are indistinguishable by fan-out alone); and the late C2 detection noted above.
The CIC captures' 96-byte snap length also means DGA behaviour on their truncated names may differ from
full-length names.

---

# Fourth step: slow periodic beaconing (30 October 2026)

The late C2 detection (73.6 of 95 minutes) was a design limit, not a threshold: the 60-second history
cannot see a beacon that calls home once a minute. Real Neris peers beacon at 58-122 s with variation
0.00-0.01, so a long-horizon tracker was added ([Slow beacon detection](SLOW_BEACON_DETECTION.md)) with
a 0.1 variation limit chosen from the data before it was built. Result on the held-out Neris test slice:
**first correct alert at 9.4 minutes instead of 73.6**, 21 of 22 C2 alerts correct, benign false alerts
unchanged on every benign capture (0 C2 alerts on 236,845 benign DNS events). Evidence:
`docs/verification/slow-beacon-20261030/`. The remaining caveats above (one family, time slices) still apply.


# Fifth step: floods on a real IoT botnet capture (30 October 2026)

Source: Stratosphere IoT-23, **Capture-34-1** (Mirai-family bot 192.168.1.195, open download from
`mcfp.felk.cvut.cz`, `2018-12-21-15-50-14-192.168.1.195.pcap`, 126 MB, 24 h, 233,865 packets, 170,980 events).
Ground truth comes from the dataset's own Zeek `conn.log.labeled` flows (labels, times, targets), not from our
alerts. Labels: `data/lab/iot23/capture-34-1.labels.json`; evidence: `docs/verification/iot23-20261030/`.

What the bot really did (checked on the raw packets): a **pure-SYN flood** (40,568 packets of 60 bytes to
71.61.66.148:80), a **flag-abuse flood** (28,431 packets of 1,078 bytes with flags SYN+PSH+ACK+URG to
123.59.209.185:80, 800-1,500 packets/s for 32 s), IRC command-and-control to 185.244.25.235:6667 all day, and
two further pure-SYN bursts (38,060 and 19,437 packets) that IoT-23 labels as a port scan and as nothing.

| Measurement | Before | After the fix |
| --- | --- | --- |
| Labelled DDoS episodes detected | 1 of 2 (pure SYN flood in 5.4 s; the SYN+PSH+ACK+URG flood missed) | **2 of 2**, median time to detect 7.9 s |
| DDoS alerts judged against IoT-23's own labels | 3 alerts, 1 correct | 4 alerts, 2 correct; the 2 others are the unlabelled pure-SYN bursts |
| Same, with the two bursts audited as DDoS from raw packets (`capture-34-1.audited.labels.json`) | 3 of 4 episodes | **4 of 4, precision 1.00, 0 false DDoS alerts** |
| Botnet C2 (IRC, 6,706 flows) | detected, time to detect 305 s, precision 0.98 | unchanged |

**The fix:** the SYN-flood rule counted only pure SYN packets, so a flood of SYN+ACK-flagged packets was invisible.
The rate window now also tracks the SYN+ACK share of a target's packets, and the same 1,000 packets/s and 70%
conditions flag it as `ddos_subtype=syn_ack_flood` (no new thresholds, no tuning). Regression: DDOS and
RECONNAISSANCE results on all earlier real captures (CTU-13 train/validation/test, the DNS set) are identical,
with zero benign DDoS alerts; 4 new tests, 869 existing tests pass, demo traces unchanged.

**Limits, stated plainly:**
- One bot, one capture, two flood types: this is evidence of detection, not a recall estimate. The audit
  relabelling of two bursts was decided from raw packets, but it was done after seeing our alerts, so the
  official-label column is the conservative number.
- **Time to detect for the flag-abuse flood is about 8-10 s** because the rule needs a full 10 s window above 1,000 packets/s.
  Floods below 1,000 packets/s are not alerted by this rule.
- 21 BOTNET_C2 alerts are the infected device's own exact 5 s DNS retries to its router (periodic, `iat_cv`
  0.0003). They are unlabelled in IoT-23 and counted as false alerts here, though they are plausibly malware
  behaviour (failing to resolve its C2 name).
- 3 DATA_EXFILTRATION alerts fire on the flood and C2 connections: the egress budget is per source, so flood
  bytes (over 20 MB in 60 s) are attributed to whichever destination the source touched at that moment.
  Content is not inspected; the alerts say "possible exfiltration" and are wrong about intent in this capture.

## Sixth step: reconnaissance on IoT-23 Capture-1-1 (30 October 2026)

Source: Stratosphere IoT-23 Capture-1-1 (Mirai-family bot 192.168.100.103, open download, `2018-05-09-192.168.100.103.pcap`,
146 MB, 1,653,042 events). Labels: `data/lab/iot23/capture-1-1.labels.json` (Zeek `PartOfAHorizontalPortScan`, 4,000 flows
on ports 23/2323/8080/9527 across about 1,400 hosts, 09 May 15:30-16:15 UTC); report: `docs/verification/iot23-20261030/1-1-report.json`.
No code or thresholds changed.

- **Scan episode detected: 1 of 1, first alert 2.0 s after the episode's first event.**
- The scorer reports 13,280 "benign" reconnaissance alerts. These are **not clean false positives**: alert sources are
  almost entirely the same infected bot (192.168.100.103) scanning outside the labelled 45 minutes (09 and 10 May), plus a
  handful of external hosts probing inward. IoT-23 labels only a capped subset of flows, so precision (0.01) here
  measures label coverage, not detector error. A trustworthy precision needs a labelled-benign window from a
  clean host, which this capture lacks.
- 11 BOTNET_C2 alerts are unlabelled (8 labelled C&C flows are single UDP contacts, too few to be beaconing); not judged.
- Not measured: slow-HTTP/slow-read, exfiltration and encrypted malware still have no suitable open capture.

## Seventh step: local-resolver DNS is not C2 (30 October 2026)

The 21 false BOTNET_C2 alerts on IoT-23 34-1 were the bot's exact 5 s UDP/53 retries to its router. The pipeline now
skips C2 for UDP port 53 toward a private address (DNS-borne C2 is the DNS tunnelling and DGA detectors' job).
Rescored (`docs/verification/iot23-20261030/34-1-after-resolver-guard.json`): 34-1 benign C2 false alerts **21 to 0**,
IRC C2 still detected; CTU-13 train/validation/test and DNS C2 results identical (all episodes still detected).
Limit: a beacon sent to a private resolver on port 53 is no longer a C2 alert; it can still raise tunnelling/DGA alerts.
Tests: `tests/test_c2_local_resolver_guard.py`; 875 pass; pins refrozen.

## Eighth step: browsing fan-out is not reconnaissance (31 October 2026)

Benign web/QUIC browsing (many destinations, no connection attempts) raised RECONNAISSANCE alerts on the DNS lab
captures. Two guards were added in `detection/pipeline.py`: recon is skipped when a TLS or QUIC session was observed
(a completed handshake is not a probe), and when the source's SYN share is below `RECON_MIN_SYN_FRACTION` (0.1, in
`detection/rule_thresholds.py`) for TCP, or for sources with some TCP SYNs. Pure-UDP scans are not affected.
Rescored: DNS lab benign recon alerts **2 to 0**; IoT-23 1-1 Telnet scan still detected 1/1 at ~2.0 s, with the same
alert count as before. The 2 CTU-13 normal-host alerts (10-SYN probes to ports 3128/1433) are kept: they look like scans.
Limit: a scanner that completes TLS/QUIC handshakes, or hides probes among many non-SYN packets, would be skipped.
Tests: 4 added to `tests/test_ddos_recon_guards.py`; 879 pass; pins refrozen. Evidence:
`docs/verification/iot23-20261030/1-1-after-recon-guards.json`.

## Ninth step: readable-word names and DGA alerts (31 October 2026)

`detection/dga_words.py` skips a DGA alert when the registrable label splits fully into words from a small curated
English/web list (hyphen parts checked separately; single words and labels with digits are not skipped). The list
excludes words taken from the benign alerts under test. Rescored on the DNS lab: benign DGA alerts **12 to 11**
(a small gain), DNS tunnelling still 1/1. Most remaining false alerts are non-English names (German, Polish,
Portuguese) or contain digits, which an English list cannot clear. Cost: about 1% of matsnu (a dictionary-word DGA)
is now skipped; banjori, corebot, dircrypt, necurs and ramnit (1,000 names each) are unaffected.
Tests: `tests/test_dga_readable_words.py`; 882 pass; pins refrozen. A fuller fix would need a multilingual
dictionary or a model trained on readable benign names, which was not attempted.

## Tenth step: monitoring traffic is not C2 (31 October 2026)

No benign slow-beacon alert exists on any capture held (CTU-13 train/validation/test, IoT-23 34-1), so the
"health checks as slow beacons" concern is not supported by data. The real benign C2 false alerts were the fast rule
firing on fixed-cadence monitoring: SNMP polling (UDP 161) and ICMP echo between hosts on one network. The pipeline now
skips C2 for those two when source and destination are both private or share an IPv4 /24 (`detection/local_network.py`).
A first version using private addresses only had no effect, because the CTU-13 hosts use public address space.
Rescored on all CTU-13 splits: benign C2 false alerts **8 to 1** (the remaining one is inbound RDP from a public host),
Neris episodes still 3/3. Limit: C2 carried over SNMP or ICMP inside one subnet is now skipped.
Tests: `tests/test_c2_monitoring_guard.py`; 885 pass; pins refrozen.

## Eleventh step: multilingual word list tried for DGA false alerts, not adopted (31 October 2026)

Source: top 3,000 words (5+ ASCII letters) of de/pl/pt/es/fr/it/nl from hermitdave/FrequencyWords (MIT,
OpenSubtitles), 11,845 words, seven files of about 650 KB each, kept out of git. Banjori, corebot, dircrypt, necurs,
ramnit and random strings stayed at 0% cleared (up to 20,000 words per language tested), but matsnu, a dictionary-word
DGA, rose from about 1% to about 4% cleared. Benign DGA alerts on the DNS lab stayed at **11 (no change)**: the
remaining names are place names, compounds and rarer words, not common vocabulary. Reverted; the English guard of the
ninth step stays. Closing this line of work needs a model trained on readable benign names, not a larger word list.

## Twelfth step: slow-HTTP on the Ulm SUEE1 capture, not detected (1 November 2026)

Source: `SUEE1.pcap` (163,705,594 bytes, release v1.1 of github.com/vs-uulm/2017-SUEE-data-set; no licence stated),
kept out of git. It mixes 150 labelled attacker hosts (slowloris, slowhttptest, slowloris-ng; `10.128.0.1-150`)
against one web server (`192.168.1.9:80`) into 2,089,436 events. The authors say `10.128.0.50` and `.100` are used
twice and should be left out of an evaluation.
**Result: the pipeline raised no DDoS alert (0 detected).** It raised 17 RECONNAISSANCE alerts from `192.168.0.1`,
not judged.
Why, from `python -m datasets.profile_suee_slow_http`: the 997 attacker connections have a median lifetime of 7 s (only
90 last 30 s or more) and about 2 connections per attacker, so no client reaches the 50 long, slow connections the
detector needs; most attack packets are 40-60 bytes, below its 61-byte data threshold. The capture is also not time-ordered
(342 backward timestamp steps, the largest about 71 minutes), so attack windows cannot be defined cleanly and no label file
was written.
Not changed: a server-level rule counting slow connections across clients would also match chat and push servers, and one
capture is not enough to tune it safely. Slow-HTTP detection stays measured on synthetic and unit tests only, with this
real capture recorded as a miss for distributed short-lived slow attacks.

## Thirteenth step: exfiltration and encrypted-malware data search, nothing usable found (1 November 2026)

The University of Twente "Data Exfiltration Malware" page (`utwente.nl/en/eemcs/scs/downloads/20171127_DEM`) returns
HTTP 404 and the group's site no longer lists it. An extended web search found no open, directly downloadable,
labelled exfiltration or encrypted-malware PCAP set: the candidates were a Google-Drive-gated malware corpus
(Root0ne/malware-pcap-dataset, download link unconfirmed, live-malware payloads), the password-protected
malware-traffic-analysis.net zips (live samples, no confirmed TLS-malware capture, file-level labels only) and 2.9 TB
DEDALE. None was downloaded. DATA_EXFILTRATION and ENCRYPTED_MALWARE therefore remain unmeasured on real captures.

## Fourteenth step: natural-language guard on the DGA rule (1 November 2026)

All 11 benign DGA alerts on the DNS lab were long (20+ letter) readable names. The DGA rule path now also requires a
vowel share below `DGA_NATURAL_VOWEL_SHARE` = 0.36 (`detection/rule_thresholds.py`): natural-language names run about
0.38 vowels per letter, generated names measured 0.14-0.20 in the UMUDGA families. First tries at 0.30 and 0.33 were too
low: the frozen demo contains a random 23-letter name at 0.348 and its alert trace changed, so the cutoff was raised to
0.36 and the demo is unchanged. Rescored: benign DGA alerts on the DNS lab **11 to 6**, DNS tunnelling still 1/1; the
guard clears 4 of 478 names the rule catches in six UMUDGA families (0.8 per cent).
Caveats: the cutoff was set after seeing both the demo failure and the 11 domains, so 11 to 6 is a development number
with no independent holdout; the remaining 6 are consonant-heavy compounds and place names (vowel share 0.26-0.35).
Tests: `tests/test_dga_natural_language_guard.py`; 887 pass; pins refrozen.

## Fifteenth step: loopback lab and SYN+ACK fix (2 November 2026)

`datasets/lab_pcap_generator.py` writes a labelled PCAP straight to disk (seed 26145, reserved documentation and
benchmark addresses, nothing ever transmitted). Scenarios: single-client slow-HTTP, slow-read, UDP reflection
amplification, bulk-upload exfiltration, plus a nightly backup and a large download as benign look-alikes, over light
web background. Scored with `python -m datasets.evaluate_lab data/lab/generated/loopback-lab-v1.labels.json`
(report: `docs/verification/lab-generated-20261101/report.json`).

| Result | Value |
|---|---|
| DDoS episodes detected | 3 / 3 |
| Exfiltration episodes detected | 1 / 1 |
| Benign alerts | 2, both `DATA_EXFILTRATION` (backup, download) |
| Benign events | 71,818 (0.028 false alerts per 1,000) |

The first run raised 28 benign `RECONNAISSANCE` alerts from the lab web server. Cause: its SYN+ACK replies counted as
scan SYN probes in `features/source_history.py`. `is_probe_syn` now counts only SYN without ACK. Recon false alerts on
the lab went 28 to 0; the IoT-23 `capture-1-1` Telnet scan is still 1/1 at about 2 s; the demo manifest is unchanged.

Limits: the backup and download alerts are the known volume overlap (a detector of volume cannot see intent). The
generator and the detectors are written by the same project, so this measures the packet parser and the tuned rules
on scripted traffic, not independent real-world accuracy. Distributed slow-HTTP remains undetected.

Tests: `tests/test_recon_server_replies.py`; 889 pass.

## Sixteenth step: SAPPAN APT29-style capture (2 November 2026)

Source: [SAPPAN Advanced Threat Data](https://zenodo.org/record/5547862), Zenodo, CC BY 4.0. Downloaded
`network_traffic_capture.pcap` (28.0 MB, md5 verified) and `test_protocol.xlsx` (14.6 kB). A simulated attack
(POshC2 implant, not real malware in the wild) on two Windows workstations: C2 over HTTPS from 172.18.3.31 and
172.18.3.32 to the attacker 10.0.11.111, a 4.6 MB `Draft.zip` pulled from Workstation1, a second extraction via
Workstation2. The record has no ground-truth labels: the episodes in `data/lab/sappan/sappan.labels.json` are my
reading of the protocol's step times (UTC, 2021-02-08 12:37 to 13:28), labelled by the attacker address only, so
alerts to other destinations count as unlabelled. Report: `docs/verification/sappan-20261102/report.json`.

The capture uses Linux cooked framing (link type 113), which the runtime reader rejects by design. The offline
converter `datasets/sll_to_ethernet.py` rewrites it to Ethernet bytes for scoring; the runtime contract is unchanged.

| Episode (label) | Alerts raised | Detected as labelled |
|---|---|---|
| C2 beaconing, 2 episodes (`BOTNET_C2`) | 34 `ENCRYPTED_MALWARE`, 0 `BOTNET_C2` | 0 / 2 |
| Exfiltration, 2 episodes (`DATA_EXFILTRATION`) | 3 `ENCRYPTED_MALWARE`, 0 `DATA_EXFILTRATION` | 0 / 2 |

What this shows:
- Every attacker episode was flagged. All 37 `ENCRYPTED_MALWARE` alerts fall on the attacker channel, the first about
  two minutes after the implant started, with no benign alert on labelled-benign traffic. The attacker's HTTPS channel
  is therefore seen, under the encrypted-malware class rather than the botnet-C2 class I had labelled. POshC2 over TLS
  fits both classes; I labelled it `BOTNET_C2` before scoring and did not relabel afterwards.
- Exfiltration is missed by design. `Draft.zip` is 4.6 MB and the rule needs 20 MB in 60 s from one source, so no
  `DATA_EXFILTRATION` alert fires. Lowering the threshold would also alert on backups and downloads (Fifteenth step).
- 10 `BOTNET_C2` alerts fire on workstation connections to cloud addresses (51.103.5.159, 54.194.126.28,
  52.210.46.20, 52.17.49.227). They are outside the attacker label so they count as false alerts here
  (0.76 per 1,000 benign events, 13,146 events), but the protocol does not say they are benign, so this is unverified.

Limits: one scripted scenario, hand-derived labels, nothing here is an accuracy estimate.
Tests: `tests/test_sll_to_ethernet.py`.

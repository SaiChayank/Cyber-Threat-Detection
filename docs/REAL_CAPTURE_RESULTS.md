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

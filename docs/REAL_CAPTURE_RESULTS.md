# First measurement on real public captures (P0-5, partial)

29 October 2026. These are the project's first results on real packet captures. They
cover **botnet C2 beaconing and benign traffic only**; every other detector remains
unmeasured on real traffic. Evidence: `docs/verification/ctu13-lab-20261029/`.

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

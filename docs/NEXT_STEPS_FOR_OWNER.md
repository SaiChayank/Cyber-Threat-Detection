# Next steps for the project owner (17 November 2026)

The code, tests and documentation are complete and pushed. The remaining gaps can only be closed with real traffic
captures that the project does not have. This page says what to get, how to hand it over, and what happens next.

## What is still open, and what data closes it

| Gap | Data that would close it |
|---|---|
| Exfiltration vs backup | Days of normal traffic from a few hosts (including backups and uploads) plus any labelled exfiltration |
| Low-rate floods (under 1,000 pps) | Normal busy-link traffic, plus a labelled low-rate flood if available |
| Distributed slow-HTTP | Traffic in front of a real web server, plus a labelled slow-HTTP attack if available |
| DGA recall (about 6%) | Real DNS traffic from a normal network (for the false-alert cost of a stronger rule) |
| SAPPAN C2 class | More labelled command-and-control captures over HTTPS |

## Option 1: ask the organisers (best)

Suggested message:

> Subject: PS26145 – sample traffic for evaluation
>
> Hello, we are working on PS26145 (AI-based detection of cyber threats in unidirectional IP traffic).
> Could you share any sample or test captures (PCAP, PCAPNG, NetFlow or IPFIX), ideally with labels or a short
> description of which hosts and time windows contain attacks? If none are available, please confirm whether
> evaluation on public and simulated data is acceptable. Thank you.

## Option 2: capture your own traffic (only where you are allowed)

Capture only on a network you own or have written permission to monitor, such as a home network or a college lab with
the administrator's approval. Never run attacks against systems you do not own.

- Windows: install Wireshark, pick the network interface, start capturing, then save as `.pcapng`.
- Linux: `sudo tcpdump -i eth0 -w capture.pcap` (use a real interface name; `-i any` also works, the converter
  `datasets/sll_to_ethernet.py` handles it).
- Keep a simple note of anything unusual you did and when (time, which machine), for example
  "14:05 to 14:20 copied a 2 GB backup from laptop to NAS". That note becomes the labels.

## How to hand data over

1. Put the files in `data/raw/<short-name>/` (this folder is git-ignored, so the data is never pushed).
2. Tell Claude the file names and paste your notes about times and hosts.
3. Claude will write the label file, run `python -m datasets.evaluate_lab`, fix what the results show, re-run every
   test, document the results in `docs/REAL_CAPTURE_RESULTS.md` and push.

## If no data arrives

Submit as it is. The system works end to end, 891 backend and 3 frontend tests pass, and every limit is written
down in [Current status](CURRENT_STATUS.md) and [Real capture results](REAL_CAPTURE_RESULTS.md). Be ready to say
plainly in a review what is measured on real traffic and what is not.

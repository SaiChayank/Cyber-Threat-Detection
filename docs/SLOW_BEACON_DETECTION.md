# Slow periodic beaconing

30 October 2026. Passive metadata only; request contents are never inspected.

## Why

The beaconing rule reads a 60-second per-source history, so a bot that phones home once a minute or
less often can never accumulate the 8 same-peer events it needs. Real Neris botnet traffic showed
exactly this: its peers beacon at 58 to 122 second intervals with variation of 0.000 to 0.01 (up to
366 contacts each), and the first correct alert on the held-out test slice came 73.6 minutes in.

## How (`features/beacon_tracker.py`, `detection/rule_thresholds.py`)

Per (source, destination, destination port) the tracker keeps the last 24 contact times (bounded:
8,192 peers). Events within 2 s of the previous contact count once, so the many packets of one
connection are one contact; a 2-hour silence starts a new series. Over the latest 10 contacts it
reports the mean gap and the coefficient of variation. State is copy-on-write, so a failed event
leaves no trace.

A `BOTNET_C2` alert is raised when all hold: at least 10 contacts, mean gap between 8 s and 1,800 s,
variation at most 0.1 (`SLOW_C2_*` in `rule_thresholds.py`; tunable with `datasets/tune_lab.py`).
Never counted: multicast and broadcast destinations (including any IPv4 address ending `.255`) and the
legitimately periodic service ports 53, 67, 68, 123, 137, 138, 161, 1900, 5353 and 5355. A persistent
beacon alerts once per source/destination per hour (`SLOW_C2_DEDUP_S`) instead of once per call-home.
The alert carries the usual C2 evidence plus `slow_beacon_events`, `slow_beacon_mean_s`,
`slow_beacon_cv`, `slow_beacon_peer` and `c2_basis=slow_periodic_contact`.

## Measured on real captures (evidence: `docs/verification/slow-beacon-20261030/`)

| Data | Before | After |
| --- | --- | --- |
| Neris held-out test slice | first correct alert at 73.6 min; 11 C2 alerts, 10 correct | first correct alert at **9.4 min**; 22 alerts, 21 correct (precision 0.95) |
| Neris train+validation slices | median 60.0 min to detect; 21 alerts, 14 correct | median **12.9 min**; 53 alerts, 46 correct |
| Benign false alerts per 1,000 events (CTU normal, Burgos, CIC) | 0.20 / 0.74 / 0.068 | **unchanged** (0 new false alerts; 0 C2 alerts on 236,845 benign DNS events) |

The 0.1 limit was chosen from the data before building: benign periodic peers measured 0.16 and above
(443 sessions) or were broadcasts and service ports that are now excluded; the botnet measured under 0.01.

## Limits

- Health checks, monitoring and keep-alives that run at a fixed interval to a service on an
  unexcluded port look identical to a beacon by timing alone; label them as benign look-alikes in lab
  captures and tune `SLOW_C2_MAX_CV` (this is the same intent ambiguity as backups versus exfiltration).
- Beacons with deliberate random jitter above 10% variation are not caught by this rule.
- Rotating destinations are tracked per destination, so a bot that changes peers every call is missed.
- One family (Neris) in one recording was measured; the setting is development evidence, not proof of
  generalisation (see [Real capture results](REAL_CAPTURE_RESULTS.md)).
- The core benchmark repeats its scenarios on a fixed schedule, which is genuinely periodic contact:
  its alert count rose from 1,170 to 2,322 and its rate from about 2,700 to about 2,000-2,500
  events/s at the time (the extra cost was SQLite alert commits; an in-process A/B showed no measurable
  tracker overhead on the PCAP path). The later SQLite `synchronous=NORMAL` change restored a wide margin
  (about 5,000 events/s; see [Performance, 30 Oct](PERFORMANCE_20261030.md)).

Tests: `tests/test_slow_beacon.py`.

"""Long-horizon periodicity of repeated contact between one source and one service.

The 60-second source history cannot see a beacon that calls home once a minute or
less often. This tracker keeps, per (source, destination, destination port), the last
KEEP contact times (contacts closer together than COALESCE_MS count once, so the many
packets of one connection are one contact) and reports the mean gap and coefficient of
variation of the latest WINDOW contacts. Memory is bounded (MAX_PEERS peers, KEEP
timestamps each) and updates are copy-on-write, so a failed event leaves no trace.
Multicast, broadcast and TCP/UDP-less traffic are ignored; service ports whose
traffic is legitimately periodic are excluded by the caller's thresholds.
"""
import math

from features.cow_map import CowMap, shallow

COALESCE_MS = 2000
RESET_GAP_MS = 2 * 3600 * 1000  # A silence this long starts a new series
KEEP = 24
WINDOW = 10
MAX_PEERS = 8192


def ignored(event):
    destination = event.dst_ip
    return (event.protocol not in (6, 17) or destination.is_multicast or str(destination) == '255.255.255.255'
            or (destination.version == 4 and str(destination).endswith('.255')))


class BeaconTracker:
    def __init__(self):
        self.series = CowMap(MAX_PEERS)  # (src, dst, port) -> tuple of contact times (ms)

    def fork(self, event):
        staged = shallow(self)
        staged.series = self.series.fork()
        return staged

    def update(self, event):
        if ignored(event):
            return empty()
        key = (event.src_ip, event.dst_ip, event.dst_port)
        times = self.series.get(key, ())
        now = event.timestamp
        if times and now - times[-1] >= COALESCE_MS:
            if now - times[-1] > RESET_GAP_MS:
                times = ()
            times = (times + (now,))[-KEEP:]
            self.series.set(key, times)
        elif not times:
            times = (now,)
            self.series.set(key, times)
        recent = times[-WINDOW:]
        if len(recent) < WINDOW:
            return empty(len(times))
        gaps = [(b - a) / 1000 for a, b in zip(recent, recent[1:])]
        mean = sum(gaps) / len(gaps)
        variation = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps)) / mean if mean else 9.0
        return dict(slow_beacon_events=len(times), slow_beacon_mean_s=mean, slow_beacon_cv=variation)


def empty(events=0):
    return dict(slow_beacon_events=events, slow_beacon_mean_s=0.0, slow_beacon_cv=9.0)


EVIDENCE = ['slow_beacon_events', 'slow_beacon_mean_s', 'slow_beacon_cv']  # The peer label is added to the alert only

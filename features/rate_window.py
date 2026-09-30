"""Bounded, causal rate aggregates; packet totals never depend on buffer length."""
import math
from collections import Counter, deque
from dataclasses import dataclass, field


@dataclass
class Bucket:
    second: int
    packets: int = 0
    bytes: int = 0
    syn_packets: int = 0
    unknown_syn_packets: int = 0
    summary_events: int = 0
    sources: Counter = field(default_factory=Counter)


class RateWindow:
    """Ten-second rates with one-second buckets and bounded source identities.

    The oldest partially overlapping second is retained: at most one extra second
    can contribute. Default entropy uses observation counts, matching the frozen
    model contract; a target SYN window can weight source counts by packets.
    Sources beyond the identity limit share an overflow group, so entropy becomes
    a disclosed lower bound. Packet and byte totals remain complete.
    """
    seconds = 10
    resolution_ms = 1000

    def __init__(self, max_sources=4096, source_weight_packets=False):
        if max_sources < 1:
            raise ValueError('Rate window needs at least one source slot')
        self.max_sources = max_sources
        self.source_weight_packets = source_weight_packets
        self.buckets = deque()
        self.sources = Counter()
        self.packets = self.bytes = self.observations = 0
        self.syn_packets = self.unknown_syn_packets = self.summary_events = 0
        self.count_log_sum = 0.0

    def _count(self, source, change):
        previous = self.sources.get(source, 0)
        current = previous + change
        if previous:
            self.count_log_sum -= previous * math.log2(previous)
        if current:
            self.sources[source] = current
            self.count_log_sum += current * math.log2(current)
        else:
            self.sources.pop(source, None)
        self.observations += change

    def update(self, event):
        second = int(event.timestamp // self.resolution_ms)
        while self.buckets and self.buckets[0].second < second - self.seconds:
            expired = self.buckets.popleft()
            self.packets -= expired.packets
            self.bytes -= expired.bytes
            self.syn_packets -= expired.syn_packets
            self.unknown_syn_packets -= expired.unknown_syn_packets
            self.summary_events -= expired.summary_events
            for source, count in expired.sources.items():
                self._count(source, -count)
        if not self.buckets or self.buckets[-1].second != second:
            self.buckets.append(Bucket(second))
        source = str(event.src_ip)
        identities = len(self.sources) - int(None in self.sources)
        if source not in self.sources and (identities >= self.max_sources or None in self.sources):
            source = None  # Overflow identity; never silently discard traffic totals.
        bucket = self.buckets[-1]
        weight = event.packets if self.source_weight_packets else 1
        syn_packets = (event.syn_packets if event.syn_packets is not None else
                       int(event.syn) if event.packets == 1 else 0) if event.protocol == 6 else 0
        unknown_syn_packets = event.packets if event.protocol == 6 and event.packets > 1 and event.syn_packets is None else 0
        summary_event = int(event.packets > 1)
        bucket.packets += event.packets
        bucket.bytes += event.bytes
        bucket.syn_packets += syn_packets
        bucket.unknown_syn_packets += unknown_syn_packets
        bucket.summary_events += summary_event
        bucket.sources[source] += weight
        self.packets += event.packets
        self.bytes += event.bytes
        self.syn_packets += syn_packets
        self.unknown_syn_packets += unknown_syn_packets
        self.summary_events += summary_event
        self._count(source, weight)
        entropy = max(0.0, math.log2(self.observations) - self.count_log_sum / self.observations)
        return dict(packet_rate=self.packets / self.seconds,
                    byte_rate=self.bytes / self.seconds, source_entropy=entropy,
                    source_count_lower_bound=len(self.sources),
                    syn_fraction=(self.syn_packets / self.packets
                                  if self.packets and not self.unknown_syn_packets else None),
                    syn_fraction_basis=('unavailable' if self.unknown_syn_packets else
                                        'declared_summary_counts' if self.summary_events else 'packet_exact'),
                    source_entropy_partial=bool(self.sources.get(None)),
                    rate_window_seconds=self.seconds,
                    rate_window_resolution_ms=self.resolution_ms)

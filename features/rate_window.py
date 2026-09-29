"""Bounded, causal rate aggregates; packet totals never depend on buffer length."""
import math
from collections import Counter, deque
from dataclasses import dataclass, field


@dataclass
class Bucket:
    second: int
    packets: int = 0
    bytes: int = 0
    sources: Counter = field(default_factory=Counter)


class RateWindow:
    """Ten-second rates with one-second buckets and bounded source identities.

    The oldest partially overlapping second is retained: at most one extra second
    can contribute. Entropy uses observation counts, matching the model contract.
    Sources beyond the identity limit share an overflow group, so entropy becomes
    a disclosed lower bound. Packet and byte totals remain complete.
    """
    seconds = 10
    resolution_ms = 1000

    def __init__(self, max_sources=4096):
        if max_sources < 1:
            raise ValueError('Rate window needs at least one source slot')
        self.max_sources = max_sources
        self.buckets = deque()
        self.sources = Counter()
        self.packets = self.bytes = self.observations = 0
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
            for source, count in expired.sources.items():
                self._count(source, -count)
        if not self.buckets or self.buckets[-1].second != second:
            self.buckets.append(Bucket(second))
        source = str(event.src_ip)
        identities = len(self.sources) - int(None in self.sources)
        if source not in self.sources and (identities >= self.max_sources or None in self.sources):
            source = None  # Overflow identity; never silently discard traffic totals.
        bucket = self.buckets[-1]
        bucket.packets += event.packets
        bucket.bytes += event.bytes
        bucket.sources[source] += 1
        self.packets += event.packets
        self.bytes += event.bytes
        self._count(source, 1)
        entropy = max(0.0, math.log2(self.observations) - self.count_log_sum / self.observations)
        return dict(packet_rate=self.packets / self.seconds,
                    byte_rate=self.bytes / self.seconds, source_entropy=entropy,
                    source_entropy_partial=bool(self.sources.get(None)),
                    rate_window_seconds=self.seconds,
                    rate_window_resolution_ms=self.resolution_ms)

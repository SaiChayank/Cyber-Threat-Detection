"""Bounded per-source event history with O(1) answers to the extractor's scans.

Behaves like the deque it replaces (iteration, len, indexing, popleft, append with
maxlen eviction) and keeps up to date, incrementally, what the extractor used to
recompute by scanning every retained event on every update:

- the running byte total of the retained events;
- the 10-second window ending at the newest event: its event count, SYN count and
  distinct destination addresses and ports;
- the retained events for one (destination, port) peer, in arrival order.

History is time-ordered (late events are dropped before they reach it), so the
window is always a suffix and results are identical to the full scans, which
keeps features and alerts unchanged. copy() is cheap: peer lists are shared until
one is modified.
"""
from collections import deque

WINDOW_MS = 10_000


class SourceHistory:
    __slots__ = ('events', 'maxlen', 'total_bytes', 'peers', '_owned',
                 'recent', 'recent_syn', 'recent_dst', 'recent_ports')

    def __init__(self, maxlen):
        self.events = deque()
        self.maxlen = maxlen
        self.total_bytes = 0
        self.peers = {}  # (dst_ip, dst_port) -> deque of this source's events, oldest first
        self._owned = set()
        self.recent = deque()  # Events within WINDOW_MS of the newest, oldest first
        self.recent_syn = 0
        self.recent_dst = {}
        self.recent_ports = {}

    def copy(self):
        staged = SourceHistory.__new__(SourceHistory)
        staged.events = self.events.copy()
        staged.maxlen = self.maxlen
        staged.total_bytes = self.total_bytes
        staged.peers = self.peers.copy()
        staged._owned = set()
        staged.recent = self.recent.copy()
        staged.recent_syn = self.recent_syn
        staged.recent_dst = self.recent_dst.copy()
        staged.recent_ports = self.recent_ports.copy()
        return staged

    def __len__(self):
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def __reversed__(self):
        return reversed(self.events)

    def __getitem__(self, index):
        return self.events[index]

    @staticmethod
    def key(event):
        return event.dst_ip, event.dst_port

    def _own(self, key):
        if key not in self._owned:
            self.peers[key] = self.peers[key].copy() if key in self.peers else deque()
            self._owned.add(key)
        return self.peers[key]

    def _leave_window(self):
        event = self.recent.popleft()
        self.recent_syn -= event.syn
        for counts, value in ((self.recent_dst, event.dst_ip), (self.recent_ports, event.dst_port)):
            if counts[value] == 1:
                del counts[value]
            else:
                counts[value] -= 1

    def popleft(self):
        event = self.events.popleft()
        self.total_bytes -= event.bytes
        key = self.key(event)
        peer = self._own(key)
        peer.popleft()  # The oldest retained event is also the oldest of its peer.
        if not peer:
            del self.peers[key]
            self._owned.discard(key)
        if self.recent and self.recent[0] is event:
            self._leave_window()
        return event

    def append(self, event):
        if self.maxlen is not None and len(self.events) >= self.maxlen:
            self.popleft()
        cutoff = event.timestamp - WINDOW_MS
        while self.recent and self.recent[0].timestamp < cutoff:
            self._leave_window()
        self.events.append(event)
        self.total_bytes += event.bytes
        self._own(self.key(event)).append(event)
        self.recent.append(event)
        self.recent_syn += event.syn
        self.recent_dst[event.dst_ip] = self.recent_dst.get(event.dst_ip, 0) + 1
        self.recent_ports[event.dst_port] = self.recent_ports.get(event.dst_port, 0) + 1

    def peer(self, event):
        """Retained events sharing this event's destination and port, oldest first."""
        return self.peers.get(self.key(event), ())

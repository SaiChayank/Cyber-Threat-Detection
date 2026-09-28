"""Causal bounded metadata features, shared by training and runtime."""
import math
import hashlib
from collections import Counter, OrderedDict, deque
from schemas.traffic_event import TrafficEvent

FEATURES = ['packet_rate', 'byte_rate', 'source_entropy', 'syn_fraction',
            'iat_mean', 'iat_cv', 'destination_count', 'port_count',
            'domain_entropy', 'domain_length', 'domain_digit_ratio', 'bigram_surprise',
            'txt_record', 'encrypted', 'size_cv', 'egress_bytes', 'byte_ratio',
            'reverse_available', 'fingerprint_risk', 'history_count']
DEMO_FINGERPRINT = hashlib.md5(b'771,49195-49199,0-23-65281,29-23-24,0').hexdigest()
COMMON_BIGRAMS = set('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur'.split())


def entropy(items):
    counts = Counter(items)
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


def cv(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) / max(mean, 1e-9)


class FeatureExtractor:
    def __init__(self, max_sources=4096, max_events=512):
        self.sources = OrderedDict()
        self.global_events = deque(maxlen=4096)
        self.max_sources = max_sources
        self.max_events = max_events
        self.watermark = -1.0
        self.late_events = 0
        self.evictions = 0

    def update(self, event: TrafficEvent):
        t = event.timestamp / 1000
        if t < self.watermark:
            self.late_events += 1
            return None  # Explicit drop: never poison causal state with late events.
        self.watermark = t
        src = str(event.src_ip)
        history = self.sources.pop(src, deque(maxlen=self.max_events))
        while history and history[0].timestamp < event.timestamp - 60000:
            history.popleft()
        if len(history) == self.max_events:
            self.evictions += 1
        history.append(event)
        self.sources[src] = history
        if len(self.sources) > self.max_sources:
            self.sources.popitem(last=False)
            self.evictions += 1
        while self.global_events and self.global_events[0].timestamp < event.timestamp - 10000:
            self.global_events.popleft()
        if len(self.global_events) == self.global_events.maxlen:
            self.evictions += 1
        self.global_events.append(event)
        recent = [e for e in history if e.timestamp >= event.timestamp - 10000]
        # Timing is per source/destination/service, not across unrelated browsing flows.
        peer = [e for e in history if e.dst_ip == event.dst_ip and e.dst_port == event.dst_port]
        intervals = [(b.timestamp - a.timestamp) / 1000 for a, b in zip(peer, peer[1:])]
        name = (event.dns_name or '').lower().rstrip('.')
        lexical = name.split('.')[0]
        bigrams = [lexical[i:i+2] for i in range(max(0, len(lexical)-1))]
        ratio = event.bytes / max(1, event.reverse_bytes or 0) if event.reverse_observed else None
        sizes = [e.bytes / e.packets for e in peer]
        values = [sum(e.packets for e in self.global_events) / 10,
                  sum(e.bytes for e in self.global_events) / 10,
                  entropy(str(e.src_ip) for e in self.global_events),
                  sum(e.syn for e in recent) / len(recent),
                  sum(intervals) / len(intervals) if intervals else 0, cv(intervals),
                  len(set(str(e.dst_ip) for e in recent)), len(set(e.dst_port for e in recent)),
                  entropy(lexical), len(name), sum(c.isdigit() for c in lexical) / max(1, len(lexical)),
                  sum(b not in COMMON_BIGRAMS for b in bigrams) / max(1, len(bigrams)),
                  float(event.dns_type in (10, 16) and bool(name)), float(event.encrypted), cv(sizes),
                  sum(e.bytes for e in history), ratio or 0, float(event.reverse_observed),
                  float(any(e.tls_fingerprint == DEMO_FINGERPRINT for e in peer)), len(peer)]
        return dict(zip(FEATURES, values)) | {'observed_byte_ratio': ratio,
                                             'window_partial': t - history[0].timestamp / 1000 < 60,
                                             'state_evictions': self.evictions}

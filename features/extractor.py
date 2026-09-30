"""Causal bounded metadata features, shared by training and runtime."""
import math
import hashlib
from collections import Counter, OrderedDict, deque
from schemas.traffic_event import TrafficEvent
from features.rate_window import RateWindow
from features.dns_tunnel import dns_tunnel_features
from ml.dga import lexical_features

FEATURES = ['packet_rate', 'byte_rate', 'source_entropy', 'syn_fraction',
            'iat_mean', 'iat_cv', 'destination_count', 'port_count',
            'domain_entropy', 'domain_length', 'domain_digit_ratio', 'bigram_surprise',
            'txt_record', 'encrypted', 'size_cv', 'egress_bytes', 'byte_ratio',
            'reverse_available', 'fingerprint_risk', 'history_count']
DEMO_FINGERPRINT = hashlib.md5(b'771,49195-49199,0-23-65281,29-23-24,0').hexdigest()
COMMON_BIGRAMS = set('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur'.split())


def dga_lexical_features(name):
    """Causal first-label features shared by runtime and DGA rule comparisons."""
    label = (name or '').lower().rstrip('.').split('.')[0]
    numeric = lexical_features(label)
    bigrams = [label[i:i + 2] for i in range(max(0, len(label) - 1))]
    return dict(domain_entropy=numeric['entropy'], domain_label_length=len(label),
                domain_digit_ratio=numeric['digit_ratio'],
                bigram_surprise=sum(pair not in COMMON_BIGRAMS for pair in bigrams) / max(1, len(bigrams)),
                domain_vowel_ratio=numeric['vowel_ratio'],
                domain_consonant_run=numeric['consonant_run'])


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
        self.global_rates = RateWindow(max_sources=max_sources)
        self.syn_targets = OrderedDict()
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
        rates = self.global_rates.update(event)
        syn_target = None
        if event.protocol == 6:
            target = str(event.dst_ip)
            target_window = self.syn_targets.pop(target, None)
            if target_window is None:
                target_window = RateWindow(max_sources=min(self.max_sources, 256), source_weight_packets=True)
            syn_target = target_window.update(event)
            self.syn_targets[target] = target_window
            if len(self.syn_targets) > 512:
                self.syn_targets.popitem(last=False)
        recent = [e for e in history if e.timestamp >= event.timestamp - 10000]
        # Timing is per source/destination/service, not across unrelated browsing flows.
        peer = [e for e in history if e.dst_ip == event.dst_ip and e.dst_port == event.dst_port]
        intervals = [(b.timestamp - a.timestamp) / 1000 for a, b in zip(peer, peer[1:])]
        name = (event.dns_name or '').lower().rstrip('.')
        dga = dga_lexical_features(name)
        ratio = event.bytes / max(1, event.reverse_bytes or 0) if event.reverse_observed else None
        sizes = [e.bytes / e.packets for e in peer]
        values = [rates['packet_rate'], rates['byte_rate'], rates['source_entropy'],
                  sum(e.syn for e in recent) / len(recent),
                  sum(intervals) / len(intervals) if intervals else 0, cv(intervals),
                  len(set(str(e.dst_ip) for e in recent)), len(set(e.dst_port for e in recent)),
                  dga['domain_entropy'], len(name), dga['domain_digit_ratio'], dga['bigram_surprise'],
                  float(event.dns_type in (10, 16) and bool(name)), float(event.encrypted), cv(sizes),
                  sum(e.bytes for e in history), ratio or 0, float(event.reverse_observed),
                  float(any(e.tls_fingerprint == DEMO_FINGERPRINT for e in peer)), len(peer)]
        return dict(zip(FEATURES, values)) | dns_tunnel_features(event, history) | {'observed_byte_ratio': ratio,
                                             'domain_label_length': dga['domain_label_length'],
                                             'domain_vowel_ratio': dga['domain_vowel_ratio'],
                                             'domain_consonant_run': dga['domain_consonant_run'],
                                             'source_entropy_partial': rates['source_entropy_partial'],
                                             'syn_target_packet_rate': syn_target['packet_rate'] if syn_target else 0.0,
                                             'syn_target_fraction': syn_target['syn_fraction'] if syn_target else 0.0,
                                             'syn_target_source_entropy': syn_target['source_entropy'] if syn_target else 0.0,
                                             'syn_target_source_count_lower_bound': syn_target['source_count_lower_bound'] if syn_target else 0,
                                             'syn_target_entropy_partial': syn_target['source_entropy_partial'] if syn_target else False,
                                             'syn_target_fraction_basis': syn_target['syn_fraction_basis'] if syn_target else 'not_tcp',
                                             'rate_window_seconds': rates['rate_window_seconds'],
                                             'rate_window_resolution_ms': rates['rate_window_resolution_ms'],
                                             'window_partial': t - history[0].timestamp / 1000 < 60,
                                             'state_evictions': self.evictions}

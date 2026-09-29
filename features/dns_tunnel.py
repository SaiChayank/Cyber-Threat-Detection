"""Causal, bounded features for complete passive DNS questions only."""
from collections import Counter
import math


WINDOW_MS = 10_000
MAX_RECENT = 128
FEATURE_NAMES = (
    'dns_query_visible', 'dns_label_count', 'dns_encoded_max_label_length',
    'dns_encoded_total_length', 'dns_encoded_entropy',
    'dns_base_queries_10s', 'dns_base_unique_ratio_10s',
    'dns_base_encoded_queries_10s',
)


def is_dns_question(event):
    return bool(event.dns_name) and event.dst_port == 53 and event.protocol in (6, 17)


def _entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _name_features(name):
    labels = name.lower().rstrip('.').split('.')
    # A conservative suffix proxy. It groups changing subdomains without a
    # public-suffix lookup or external DNS query; two-label names have no encoded prefix.
    base = '.'.join(labels[-2:])
    encoded = labels[:-2]
    joined = ''.join(encoded)
    return base, len(labels), max(map(len, encoded), default=0), len(joined), _entropy(joined)


def dns_tunnel_features(event, source_history):
    """Current query plus earlier same-source observations in the last 10 seconds."""
    result = dict.fromkeys(FEATURE_NAMES, 0)
    if not is_dns_question(event):
        return result
    base, count, maximum, total, lexical_entropy = _name_features(event.dns_name)
    recent = []
    for previous in reversed(source_history):
        if previous.timestamp < event.timestamp - WINDOW_MS:
            break
        if is_dns_question(previous):
            previous_base, _, previous_max, previous_total, previous_entropy = _name_features(previous.dns_name)
            if previous_base == base:
                recent.append((previous.dns_name.lower().rstrip('.'), previous_max,
                               previous_total, previous_entropy))
                if len(recent) >= MAX_RECENT:
                    break
    qualifying = sum(max_length >= 24 and length >= 32 and ent >= 3.5
                     for _, max_length, length, ent in recent)
    return {
        'dns_query_visible': 1,
        'dns_label_count': count,
        'dns_encoded_max_label_length': maximum,
        'dns_encoded_total_length': total,
        'dns_encoded_entropy': lexical_entropy,
        'dns_base_queries_10s': len(recent),
        'dns_base_unique_ratio_10s': len({name for name, *_ in recent}) / len(recent),
        'dns_base_encoded_queries_10s': qualifying,
    }

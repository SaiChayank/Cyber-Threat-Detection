"""Portable lexical DGA classifier. Runtime uses no sklearn or network access."""
import hashlib
import json
import math
import struct
from collections import Counter
from functools import lru_cache
from pathlib import Path

ARTIFACT = Path(__file__).with_name('dga_v2.json')
FEATURE_VERSION = 'first-label-char-2-3-tfidf-lexical-boosted-v3'
NUMERIC_FEATURES = ['log_length', 'entropy', 'digit_ratio', 'vowel_ratio',
                    'hyphen_ratio', 'unique_ratio', 'consonant_run', 'digit_run',
                    'digit_transitions', 'repeat_ratio']


def domain_label(domain):
    """Canonical ASCII DNS label; no suffix, address, timing or family features."""
    name = (domain or '').strip().lower().rstrip('.')
    labels = name.split('.')
    if len(labels) < 2 or len(name) > 253:
        return ''
    for label in labels:
        if not 1 <= len(label) <= 63 or label.startswith('-') or label.endswith('-'):
            return ''
        if any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label):
            return ''
    return labels[0]


def tokens(label):
    value = '^' + label + '$'
    return Counter(value[i:i + n] for n in (2, 3) for i in range(len(value) - n + 1))


def lexical_features(label):
    """Length, character composition and runs, using only the observed label."""
    counts = Counter(label)
    length = max(1, len(label))
    entropy = -sum(n / length * math.log2(n / length) for n in counts.values())
    consonant_run = digit_run = max_consonants = max_digits = 0
    for c in label:
        consonant_run = consonant_run + 1 if c in 'bcdfghjklmnpqrstvwxyz' else 0
        digit_run = digit_run + 1 if c.isdigit() else 0
        max_consonants = max(max_consonants, consonant_run)
        max_digits = max(max_digits, digit_run)
    return dict(zip(NUMERIC_FEATURES, [math.log1p(len(label)), entropy,
                sum(c.isdigit() for c in label) / length,
                sum(c in 'aeiou' for c in label) / length,
                label.count('-') / length, len(counts) / length,
                max_consonants / length, max_digits / length,
                sum(a.isdigit() != b.isdigit() for a, b in zip(label, label[1:])) / length,
                sum(a == b for a, b in zip(label, label[1:])) / length]))


class DgaModel:
    def __init__(self, path=ARTIFACT):
        self.enabled = False
        self.data = None
        if not path.is_file():
            return  # Retain the conservative guard without an optional artifact.
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != path.with_suffix('.sha256').read_text().strip():
            raise ValueError('DGA model integrity verification failed')
        self.data = json.loads(raw)
        if self.data.get('feature_version') != FEATURE_VERSION:
            raise ValueError('DGA model feature contract mismatch')
        if set(self.data.get('numeric_weights', {})) != set(NUMERIC_FEATURES):
            raise ValueError('DGA numerical feature contract mismatch')
        self.enabled = self.data['runtime_enabled']
        self.threshold = self.data['decision_threshold']
        self._score = lru_cache(maxsize=4096)(self._uncached_score)

    def _uncached_score(self, label):
        weighted_sum = squared_norm = 0.0
        for token, count in tokens(label).items():
            entry = self.data['weights'].get(token)
            if entry is None:
                continue
            coefficient, idf = entry
            value = (1 + math.log(count)) * idf
            weighted_sum += coefficient * value
            squared_norm += value * value
        logit = self.data['intercept']
        if squared_norm:
            logit += weighted_sum / math.sqrt(squared_norm)
        numeric = lexical_features(label)
        for name, value in numeric.items():
            coefficient, mean, scale = self.data['numeric_weights'][name]
            logit += coefficient * (value - mean) / scale
        # Small fixed-depth trees combine lexical composition with the character
        # model logit. Nodes contain only numbers, never executable objects.
        # sklearn tree inference compares float32 inputs with float64 thresholds.
        features = [struct.unpack('!f', struct.pack('!f', v))[0] for v in (logit, *numeric.values())]
        boosted = self.data['boosted_intercept']
        for nodes in self.data['trees']:
            index = 0
            for _ in range(4):  # Exported depth is at most three, then one leaf.
                left, right, feature, threshold, value = nodes[index]
                if left == -1:
                    boosted += self.data['learning_rate'] * value
                    break
                index = left if features[feature] <= threshold else right
            else:
                raise ValueError('DGA tree exceeds bounded inference depth')
        return 1 / (1 + math.exp(-max(-700, min(700, boosted))))

    def predict(self, domain):
        label = domain_label(domain)
        if not self.enabled or not label:
            return None  # Unsupported name or unpromoted artifact: no ML decision.
        return self._score(label)

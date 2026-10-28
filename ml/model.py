"""Portable Gaussian naive Bayes, trained from causal streaming features.

JSON artifacts avoid executable pickle loading. Confidence is a model posterior;
it is not claimed to be calibrated on real traffic.
"""
import hashlib
import json
import math
from pathlib import Path
from features.extractor import FEATURES

ARTIFACT = Path(__file__).with_name('artifact.json')


def vector(features):
    return [math.log1p(max(0, features[name])) for name in FEATURES]


class Model:
    def __init__(self, path=ARTIFACT):
        raw = path.read_bytes()
        expected = path.with_suffix('.sha256').read_text().strip()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Model integrity verification failed')
        self.data = json.loads(raw)
        if self.data['features'] != FEATURES:
            raise ValueError('Model feature contract mismatch')
        # Per-class constants hoisted out of the per-event path; same Gaussian log-likelihood.
        self._classes = [(label, math.log(stats['prior']),
                          sum(math.log(2 * math.pi * v) for v in stats['variance']),
                          stats['mean'], [1 / v for v in stats['variance']])
                         for label, stats in self.data['classes'].items()]

    def predict(self, features):
        x = vector(features)
        scores = {}
        for label, log_prior, log_norm, means, inverse in self._classes:
            scores[label] = log_prior - .5 * (log_norm + sum(
                (a - m) * (a - m) * i for a, m, i in zip(x, means, inverse)))
        peak = max(scores.values())
        weights = {k: math.exp(max(-700, s-peak)) for k, s in scores.items()}
        total = sum(weights.values())
        probs = {k: w/total for k, w in weights.items()}
        label = max(probs, key=probs.get)
        return label, probs[label]

"""Checks for diagnostic accounting; no runtime/model behavior is changed."""
import math
import hashlib
import json
from pathlib import Path

import pytest

from datasets.audit_feature_parity import changes, historical_definitions, run_probes
from features.extractor import FEATURES
from ml.model import ARTIFACT


def test_changes_covers_exact_model_order_and_ignores_float_noise():
    before = dict.fromkeys(FEATURES, 0.0)
    after = before | {'packet_rate': 1.0, 'source_entropy': 1e-12, 'rule_only': 999}
    assert changes(before, after) == {'packet_rate': {'before': 0.0, 'after': 1.0, 'delta': 1.0}}
    with pytest.raises(KeyError):
        changes(before, {})


def test_historical_probes_distinguish_missing_reverse_and_real_drift(monkeypatch):
    # Unit checks work even in source archives/shallow validation snapshots.
    # The standalone audit requires the actual pinned local Git history.
    fixture = json.loads((Path(__file__).parent/'fixtures/feature_parity_history.json').read_text())
    assert hashlib.sha256(ARTIFACT.read_bytes()).hexdigest() == fixture['model_sha256']
    def historical_blob(name):
        if name == 'ml/artifact.json':
            return ARTIFACT.read_bytes()
        item = fixture['sources'][name]
        raw = item['source'].encode()
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        return raw
    monkeypatch.setattr('datasets.audit_feature_parity.blob', historical_blob)
    old_class, _, _ = historical_definitions()
    probes = run_probes(old_class)
    assert probes['reverse_unavailable']['changes'] == {}
    assert probes['reverse_unavailable']['observed_ratio_after'] is None
    assert probes['reverse_observed_positive']['changes'] == {}
    zero = probes['reverse_observed_zero']
    assert zero['changes'] == {'byte_ratio': {'before': 100.0, 'after': 0, 'delta': -100.0}}
    assert zero['observed_ratio_after'] is None
    boundary = probes['bucket_boundary']['changes']
    assert boundary['packet_rate']['before'] == .1 and boundary['packet_rate']['after'] == 10.1
    assert boundary['source_entropy']['before'] == 0 and boundary['source_entropy']['after'] == 1
    bounded = probes['bounded_global_history']
    assert bounded['changes']['packet_rate']['before'] == 409.6
    assert bounded['changes']['packet_rate']['after'] == 409.7
    assert bounded['current_source_bytes_60s'] == 4097 * 60
    assert bounded['current_ml_egress_bytes'] == 512 * 60
    granularity = probes['packet_vs_summary']
    assert granularity['summaries']['source_entropy'] == 1
    assert granularity['packets']['source_entropy'] == pytest.approx(-.9*math.log2(.9)-.1*math.log2(.1))
    for key in ('packet_rate', 'byte_rate'):
        assert granularity['summaries'][key] == granularity['packets'][key]


def test_diagnostic_rejects_a_different_frozen_artifact(monkeypatch):
    monkeypatch.setattr('datasets.audit_feature_parity.blob', lambda _: b'{}')
    with pytest.raises(ValueError, match='differs from the pinned'):
        historical_definitions()

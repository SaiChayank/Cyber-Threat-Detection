"""Frozen training-only DGA weighting and report math."""
import hashlib
import json

from datasets.train_dga_candidate import OUTPUT, PLAN, counts, extra_weight, with_families
from ml.dga import ARTIFACT, DgaModel


def test_only_long_alphabetic_benign_labels_receive_extra_weight():
    assert extra_weight('longlegitimatename', 0) == 3
    assert extra_weight('short', 0) == 1
    assert extra_weight('abc123def456', 0) == 1
    assert extra_weight('longlegitimatename', 1) == 1
    assert extra_weight('abcdefghijkl', 0) == 3  # Exact 12-character boundary.


def test_candidate_report_math_and_family_metrics():
    result = dict(tp=8, tn=9, fp=1, fn=2, precision=8 / 9, recall=.8,
                  false_positive_rate=.1,
                  per_family={'family_a': {'recall': .5}, 'family_b': {'recall': 1.0},
                              'legit': {'recall': None}})
    assert counts(result)['f1'] == 16 / 19
    assert with_families(result)['per_family_recall'] == {'family_a': .5, 'family_b': 1.0}


def test_training_choices_are_frozen_before_validation():
    assert hashlib.sha256(PLAN.read_bytes()).hexdigest() == PLAN.with_suffix('.sha256').read_text().strip()
    plan = json.loads(PLAN.read_text())
    assert plan['validation_threshold_grid'] == [.5, .6, .7, .8, .85, .9, .95, .975, .99]
    assert 'runtime_enabled=false' in plan['candidate_output']


def test_separate_candidate_is_hash_verified_and_disabled():
    assert OUTPUT != ARTIFACT
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    assert digest == OUTPUT.with_suffix('.sha256').read_text().strip()
    candidate = DgaModel(OUTPUT)
    assert not candidate.enabled
    assert candidate.predict('xqjmtvkp.example') is None

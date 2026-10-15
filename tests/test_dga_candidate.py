"""Frozen training-only DGA weighting and report math."""
import hashlib
import json
import math

import pytest

from datasets.train_dga_candidate import OUTPUT, PLAN, counts, extra_weight, with_families
from ml.dga import ARTIFACT, DgaModel
from datasets.train_dga_candidate import (OOF_PLAN, OOF_OUTPUT, OOF_VECTORS,
    fold_for_row, out_of_fold_logits, write_new, validation_failures)


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


def test_oof_plan_is_frozen_and_preserves_features_threshold_and_gates():
    assert hashlib.sha256(OOF_PLAN.read_bytes()).hexdigest() == OOF_PLAN.with_suffix('.sha256').read_text().strip()
    plan = json.loads(OOF_PLAN.read_text())
    from ml.dga import FEATURE_VERSION, NUMERIC_FEATURES
    assert plan['feature_version'] == FEATURE_VERSION
    assert plan['numeric_features'] == NUMERIC_FEATURES
    assert plan['fixed_threshold'] == .9
    assert plan['fold_count'] == 3
    assert plan['promotion_gates']['minimum_recall'] == .8
    assert plan['promotion_gates']['minimum_precision'] == .95
    assert plan['promotion_gates']['maximum_domain_false_positive_rate'] == .02
    assert plan['promotion_gates']['maximum_separate_benign_dns_false_positive_rate'] == .02
    assert plan['artifact_runtime_enabled'] is False


def toy_oof_rows():
    positives = [('first', 1, 'alureon'), ('second', 1, 'necurs'), ('third', 1, 'corebot')]
    benign = []
    for fold in range(3):
        benign.append(next((f'benign{n}', 0, 'legit') for n in range(100)
                           if fold_for_row((f'benign{n}', 0, 'legit')) == fold))
    assert {fold_for_row(row) for row in positives} == {0, 1, 2}
    return positives + benign


def test_oof_related_variants_and_benign_labels_stay_together():
    assert fold_for_row(('one', 1, 'gozi_gpl')) == fold_for_row(('other', 1, 'gozi_nasa'))
    assert fold_for_row(('one', 1, 'suppobox_1')) == fold_for_row(('other', 1, 'suppobox_3'))
    assert fold_for_row(('same', 0, 'legit')) == fold_for_row(('same', 0, 'different-source'))


def test_oof_each_training_row_scored_once_without_its_group():
    rows = toy_oof_rows()
    seen = []
    def fit_and_score(fitted, held):
        assert not {r[0] for r in fitted} & {r[0] for r in held}
        assert not {r[2].split('_')[0] for r in fitted if r[1]} & {r[2].split('_')[0] for r in held if r[1]}
        assert {r[1] for r in fitted} == {0, 1}
        seen.extend(held)
        return [len(r[0]) for r in held]
    logits, evidence = out_of_fold_logits(rows, fit_and_score)
    assert sorted(seen) == sorted(rows)
    assert logits == [len(r[0]) for r in rows]
    assert len(evidence) == 3
    assert sum(sum(e['held_counts'].values()) for e in evidence) == len(rows)


@pytest.mark.parametrize('scores,message', [([], 'count mismatch'), ([math.nan], 'finite')])
def test_oof_rejects_incomplete_or_nonfinite_scores(scores, message):
    rows = toy_oof_rows()
    def fit_and_score(fitted, held):
        return scores if not scores else scores * len(held)
    with pytest.raises(ValueError, match=message):
        out_of_fold_logits(rows, fit_and_score)


def test_output_exclusive_create_preserves_frozen_evidence(tmp_path):
    path = tmp_path / 'frozen.json'
    write_new(path, b'unchanged')
    with pytest.raises(FileExistsError):
        write_new(path, b'replacement')
    assert path.read_bytes() == b'unchanged'


def test_validation_gate_failure_reasons_do_not_relax_bounds():
    assert validation_failures(dict(recall=.8, precision=.95, false_positive_rate=.02)) == []
    errors = validation_failures(dict(recall=.7999, precision=.9499, false_positive_rate=.0201))
    assert len(errors) == 3


def test_candidate_training_refuses_existing_output_before_fitting(tmp_path, monkeypatch):
    import datasets.train_dga_candidate as trainer
    output = tmp_path / 'frozen.json'
    output.write_bytes(b'unchanged')
    monkeypatch.setattr(trainer, 'OOF_OUTPUT', output)
    with pytest.raises(FileExistsError, match='Preserve frozen DGA output'):
        trainer.main(oof=True)
    assert output.read_bytes() == b'unchanged'


def test_oof_disabled_portable_artifact_matches_independent_validation_vectors():
    digest = hashlib.sha256(OOF_OUTPUT.read_bytes()).hexdigest()
    assert digest == OOF_OUTPUT.with_suffix('.sha256').read_text().strip()
    reference = json.loads(OOF_VECTORS.read_text())
    assert reference['model_sha256'] == digest
    model = DgaModel(OOF_OUTPUT)
    assert not model.enabled
    assert model.predict('xqjmtvkp.example') is None
    from ml.dga import domain_label
    for case in reference['cases']:
        assert model._uncached_score(domain_label(case['domain'])) == pytest.approx(
            case['expected_score'], rel=0, abs=1e-10)

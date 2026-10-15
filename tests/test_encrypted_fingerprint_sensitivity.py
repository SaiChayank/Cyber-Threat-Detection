"""Single-feature counterfactual controls; no runtime/artifact mutation."""
import json

import pytest

from datasets.encrypted_fingerprint_sensitivity import (
    REPORT, CASES, TARGET, metrics, model_verdict, paired_predictions, prediction, scenario,
)
from features.extractor import FEATURES


def test_pair_changes_only_copied_fingerprint_bit_and_preserves_observed_input():
    features = dict.fromkeys(FEATURES, 0.0) | {'fingerprint_risk':1.0, 'rule_only':42}
    snapshot = features.copy()
    calls = []
    def predict(values):
        calls.append(values.copy())
        return (TARGET, .99) if values['fingerprint_risk'] else ('BENIGN', .99)
    observed, counterfactual, before, after = paired_predictions(predict, features)
    assert features == snapshot
    assert [key for key in FEATURES if observed[key] != counterfactual[key]] == ['fingerprint_risk']
    assert calls == [observed,counterfactual]
    assert before == (TARGET,.99) and after == ('BENIGN',.99)
    assert set(calls[0]) == set(FEATURES)


def test_zero_bit_negative_control_has_identical_input_and_prediction():
    features = dict.fromkeys(FEATURES,0.0)
    a,b,before,after = paired_predictions(lambda _: ('BENIGN',.75),features)
    assert a == b and before == after
    assert a is not b and a is not features


def test_stateful_or_inconsistent_predictions_on_identical_controls_fail():
    predictions = iter([('BENIGN',.8), (TARGET,.8)])
    with pytest.raises(ValueError,match='Negative-control'):
        paired_predictions(lambda _:next(predictions),dict.fromkeys(FEATURES,0.0))


def test_unfrozen_fingerprint_representation_is_rejected():
    features = dict.fromkeys(FEATURES,0.0) | {'fingerprint_risk':2}
    with pytest.raises(ValueError,match='binary'):
        paired_predictions(lambda _:('BENIGN',1),features)


@pytest.mark.parametrize('label,posterior,hit',[(TARGET,.8,True),(TARGET,.7999,False),('BENIGN',.999,False)])
def test_existing_top_class_cutoff_is_not_a_calibrated_target_probability(label,posterior,hit):
    assert prediction(label,posterior) == dict(top_label=label,top_posterior=posterior,target_hit=hit)


def test_scenario_metric_requires_early_positive_hit_and_counts_any_benign_hit():
    assert model_verdict(True,dict(event=19),20) == 'TP'
    assert model_verdict(True,dict(event=20),20) == 'FN'
    assert model_verdict(True,None,20) == 'FN'
    assert model_verdict(False,dict(event=20),20) == 'FP'
    assert model_verdict(False,None,20) == 'TN'
    rows=[{'observed':{'verdict':value}} for value in ('TP','TN','FP','FN')]
    assert metrics(rows,'observed') == dict(TP=1,TN=1,FP=1,FN=1,precision=.5,recall=.5,f1=.5,false_positive_rate=.5)
    assert metrics([],'observed')['precision'] == 0


def saved(name):
    return next(row for row in json.loads(REPORT.read_text())['rows'] if row['scenario']==name)


@pytest.mark.parametrize('name', ['lab_tls_stable','update_shared_ja3'])
def test_counterfactual_never_drives_real_pipeline_alerts(name):
    index=next(i for i,case in enumerate(CASES) if case[0]==name)
    result=scenario(CASES[index],index,saved(name))
    assert result['observed_runtime_first_alert']['event'] == 1
    assert result['unchanged_rule_hit_events'] == 20
    assert result['changed_input_events'] == 20
    assert result['observed']['hit_events'] > 0
    assert result['counterfactual']['hit_events'] == 0
    assert result['observed_runtime_verdict'] == ('TP' if CASES[index][1] else 'FP')


def test_novel_fingerprint_control_retains_all_twenty_exact_predictions():
    index=next(i for i,case in enumerate(CASES) if case[0]=='novel_tls_stable')
    result=scenario(CASES[index],index,saved('novel_tls_stable'))
    assert result['changed_input_events'] == 0
    assert all(item['observed']==item['counterfactual'] and item['changed_features']==[]
               for item in result['comparisons'])


def test_changed_saved_stream_cannot_be_silently_used_as_new_evaluation():
    with pytest.raises(ValueError,match='scenario/label'):
        scenario(CASES[0],0,saved('lab_tls_stable') | {'stream_sha256':'changed'})

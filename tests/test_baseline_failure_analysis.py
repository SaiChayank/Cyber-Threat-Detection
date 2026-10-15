"""Diagnostic regressions; no detector/gate/artifact change."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from datasets.analyze_baseline_failures import (
    ROOT, attribution, generator_matches_report, overlaps, replay_first,
)
from datasets.validate_c2_beacon import events
from schemas.traffic_event import TrafficEvent


@pytest.mark.parametrize('source,label,posterior,model,rule', [
    ('HYBRID', 'BOTNET_C2', .95, True, True),
    ('ML', 'BOTNET_C2', .9, True, False),
    ('RULE', 'BENIGN', .99, False, True),
])
def test_source_distinguishes_target_rule_and_model_contributions(source, label, posterior, model, rule):
    result = attribution(SimpleNamespace(detection_source=source), label, posterior, 'BOTNET_C2')
    assert result['target_model_hit'] is model and result['target_rule_hit'] is rule
    assert result['model_label'] == label and result['model_posterior'] == posterior


@pytest.mark.parametrize('source,label,posterior', [
    ('RULE', 'BOTNET_C2', .99), ('ML', 'BENIGN', .99), ('HYBRID', 'BOTNET_C2', .79),
])
def test_inconsistent_attribution_never_silently_becomes_an_explanation(source, label, posterior):
    with pytest.raises(ValueError, match='disagrees'):
        attribution(SimpleNamespace(detection_source=source), label, posterior, 'BOTNET_C2')


def test_generator_pin_allows_checkout_newlines_but_not_changed_code():
    source = b'events = [1, 2]\n'
    expected = hashlib.sha256(source.replace(b'\n', b'\r\n')).hexdigest()
    assert generator_matches_report(source, expected)
    assert generator_matches_report(source.replace(b'\n', b'\r\n'), expected)
    assert not generator_matches_report(b'events = [1, 3]\n', expected)


def saved_health_check():
    report = json.loads((ROOT/'docs/verification/release-audit/c2_beacon_development.json').read_text())
    return next(row['first_alert'] for row in report['scenarios'] if row['scenario']=='health_check_2_5')


def test_existing_health_check_reproduces_actual_hybrid_hit_without_tuning():
    result = replay_first(list(events('fixed_2_5', 130)), 'BOTNET_C2', saved_health_check())
    assert result['event'] == 8 and result['elapsed_seconds'] == 17.5
    assert result['target_rule_hit'] and result['target_model_hit']
    assert result['runtime_features']['history_count'] == 8


def test_changed_first_alert_is_a_diagnostic_error_not_a_silent_new_verdict():
    saved = saved_health_check() | {'event':9}
    with pytest.raises(ValueError, match='differs from saved evaluation'):
        replay_first(list(events('fixed_2_5', 130)), 'BOTNET_C2', saved)


def test_opposite_labels_do_not_enter_features_or_hide_identical_observations():
    stream = list(events('fixed_2_5', 130))
    result = overlaps({'beacon':stream,'health':stream}, {'beacon':True,'health':False})
    assert len(result) == 1
    assert result[0]['positives'] == ['beacon'] and result[0]['benign'] == ['health']
    assert result[0]['identical_raw_event_pairs'] == [['beacon','health']]
    assert overlaps({'a':stream,'b':stream}, {'a':False,'b':False}) == []


def test_feature_collision_is_distinguished_from_identical_raw_metadata():
    base = dict(timestamp=1700000000000,src_ip='192.0.2.1',dst_ip='198.51.100.1',bytes=100)
    tcp, udp = [TrafficEvent(**base,protocol=6)], [TrafficEvent(**base,protocol=17)]
    result = overlaps({'tcp':tcp,'udp':udp},{'tcp':True,'udp':False})
    assert len(result) == 1 and result[0]['identical_raw_event_pairs'] == []

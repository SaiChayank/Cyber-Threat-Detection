"""Read-only C2 diagnostics; no new candidate or quality evaluation."""
import json

import pytest

from datasets import analyze_baseline_failures as diagnostic
from datasets.validate_c2_beacon import events


def test_identical_health_check_cannot_be_separated_by_metadata_or_features():
    stream = list(events('fixed_2_5', 130))
    result = diagnostic.c2_pair_detail(stream, stream)
    assert result == dict(metadata_identical=True, different_metadata_fields=[],
                         complete_runtime_features_identical=True, different_runtime_features=[],
                         different_model_features=[], model_vectors_identical=True,
                         c2_rule_decisions_identical=True)


def test_jittered_telemetry_is_a_rule_collision_not_identical_model_observations():
    result = diagnostic.c2_pair_detail(list(events('jitter_6', 130)),
                                       list(events('jitter_6', 256)))
    assert result['different_metadata_fields'] == ['bytes']
    assert result['different_model_features'] == ['byte_rate', 'egress_bytes']
    assert not result['complete_runtime_features_identical']
    assert not result['model_vectors_identical']
    assert result['c2_rule_decisions_identical']


@pytest.mark.parametrize('kind,maximum,first', [
    ('fixed_2_5', 25, 8), ('fixed_6', 11, 8), ('fixed_12', 6, None),
    ('fixed_20', 4, None), ('rotate_12', 3, None), ('short_6', 7, None),
])
def test_causal_horizon_trace_never_trains_or_predicts(kind, maximum, first, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('History diagnosis must not train or predict')
    monkeypatch.setattr('ml.model.Model.predict', forbidden)
    monkeypatch.setattr('ml.train.fit', forbidden)
    result = diagnostic.c2_history_detail(list(events(kind, 130)))
    assert result['max_peer_history_count'] == maximum
    assert result['first_eight_peer_event'] == first
    if kind == 'rotate_12':
        final = result['final_audited_features']
        assert final['iat_mean_seconds'] == 24
        assert final['source_destination_count_last_60s'] == 2
        assert final['destination_count_last_10s'] == 1
        assert final['peer_persistence_last_60s'] == .5


def test_invalid_pair_and_history_inputs_fail_instead_of_claiming_equality():
    stream = list(events('fixed_6', 130))
    with pytest.raises(ValueError, match='aligned'):
        diagnostic.c2_pair_detail(stream, [])
    with pytest.raises(ValueError, match='ordered'):
        diagnostic.c2_history_detail([])
    with pytest.raises(ValueError, match='ordered'):
        diagnostic.c2_history_detail(stream[::-1])
    with pytest.raises(ValueError, match='ordered'):
        diagnostic.c2_pair_detail(stream[::-1], stream)


def test_first_eight_observations_are_not_borrowed_from_the_future():
    stream = list(events('fixed_6', 130))
    seven = diagnostic.c2_history_detail(stream[:7])
    eight = diagnostic.c2_history_detail(stream[:8])
    assert seven['first_eight_peer_event'] is None
    assert seven['final_audited_features']['peer_history_count'] == 7
    assert eight['first_eight_peer_event'] == 8
    assert eight['final_audited_features']['iat_mean_seconds'] == 6


def test_c2_scope_reads_only_exposed_c2_report_and_imports_its_generator(monkeypatch):
    from ml.model import Model

    original_import = diagnostic.importlib.import_module
    original_read = diagnostic.Path.read_bytes
    original_predict = Model.predict
    reports = []
    imports = []
    predictions = []

    def observe_prediction(model, features):
        predictions.append(features['history_count'])
        return original_predict(model, features)

    def import_c2_only(name):
        assert name == 'datasets.validate_c2_beacon'
        imports.append(name)
        return original_import(name)

    def read_no_other_reports(path):
        if 'release-audit' in path.parts:
            assert path.name == 'c2_beacon_development.json'
            reports.append(path.name)
        return original_read(path)

    monkeypatch.setattr(diagnostic.importlib, 'import_module', import_c2_only)
    monkeypatch.setattr(diagnostic.Path, 'read_bytes', read_no_other_reports)
    monkeypatch.setattr(Model, 'predict', observe_prediction)
    result = diagnostic.analyze(group='C2')
    assert imports == ['datasets.validate_c2_beacon']
    assert reports == ['c2_beacon_development.json']
    assert [row['group'] for row in result['modules']] == ['C2']
    assert result['first_false_positive_sources'] == {'HYBRID': 1, 'ML': 1}
    assert len(result['modules'][0]['same_timing_pairs']) == 4
    assert len(result['modules'][0]['causal_histories']) == 14
    assert predictions == list(range(1, 9)) * 2  # Only the two known FP prefixes.
    assert not any(result['policy'].values())


@pytest.mark.parametrize('mutation,message', [('label', 'C2 labels'), ('history', 'causal history')])
def test_changed_saved_labels_or_history_cannot_be_silently_relabelled(monkeypatch, mutation, message):
    original_read = diagnostic.Path.read_bytes

    def changed_report(path):
        raw = original_read(path)
        if path.name == 'c2_beacon_development.json':
            report = json.loads(raw)
            row = report['scenarios'][0]
            if mutation == 'label':
                row['ground_truth_c2'] = False
            else:
                row['max_peer_history_count'] += 1
            return json.dumps(report).encode()
        return raw

    monkeypatch.setattr(diagnostic.Path, 'read_bytes', changed_report)
    with pytest.raises(ValueError, match=message):
        diagnostic.analyze(group='C2')

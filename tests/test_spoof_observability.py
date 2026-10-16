"""Existing suspected-spoof diagnostics, never passive proof of source forgery."""
import hashlib
import json

import pytest

from datasets import analyze_baseline_failures as diagnostic
from datasets.validate_spoofed_source import events


@pytest.mark.parametrize('kind', ['once_32', 'once_64', 'repeat_32'])
def test_opposite_emitter_provenance_does_not_change_any_visible_representation(kind):
    positive, benign = list(events(kind)), list(events(kind))
    result = diagnostic.udp_collision_detail(positive, benign)
    assert result['metadata_identical']
    assert result['different_metadata_fields'] == []
    assert result['complete_runtime_features_identical']
    assert result['model_vectors_identical']
    assert result['udp_rate_rule_decisions_identical']


def test_repeat_source_completion_cannot_replace_causal_singleton_evidence(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Causal evidence reconstruction must not predict or train')
    monkeypatch.setattr('ml.model.Model.predict', forbidden)
    monkeypatch.setattr('ml.train.fit', forbidden)
    stream = list(events('repeat_32'))
    prefix = diagnostic.spoof_history_detail(stream[:24])
    first = diagnostic.spoof_history_detail(stream[:25])
    completed = diagnostic.spoof_history_detail(stream)
    assert prefix['first_disabled_indicator'] is None
    assert first['first_disabled_indicator'] == completed['first_disabled_indicator']
    assert first['first_disabled_indicator']['event'] == 25
    assert first['first_disabled_indicator']['features']['singleton_source_fraction'] == 1
    assert completed['final_visible_features']['singleton_source_fraction'] == 0


def test_summary_singletons_are_not_single_packets_or_measured_within_flow_timing():
    stream = list(events('once_32'))
    first = diagnostic.spoof_history_detail(stream)['first_disabled_indicator']
    assert first['timestamp'] - stream[0].timestamp == 2400
    f = first['features']
    assert f['target_packet_rate'] == 1000
    assert f['target_flow_summary_rate'] == 2.5
    assert f['unique_source_count_lower_bound'] == 25
    assert all(e.packets == 400 for e in stream[:25])
    assert f['singleton_source_fraction'] == 1
    assert first['wording'] == 'consistent with suspected spoofed-source flood'


def test_telemetry_has_a_size_difference_but_the_same_rate_rule_sequence():
    result = diagnostic.udp_collision_detail(list(events('once_32')), list(events('telemetry_32')))
    assert result['different_metadata_fields'] == ['bytes']
    assert not result['model_vectors_identical']
    assert not result['complete_runtime_features_identical']
    assert result['udp_rate_rule_decisions_identical']
    assert (diagnostic.spoof_history_detail(list(events('once_32')))['diagnostic_feature_sequence_sha256'] ==
            diagnostic.spoof_history_detail(list(events('telemetry_32')))['diagnostic_feature_sequence_sha256'])


def test_target_spread_is_a_model_collision_but_not_a_complete_runtime_collision():
    result = diagnostic.udp_collision_detail(list(events('once_32')), list(events('spread')))
    assert result['different_metadata_fields'] == ['dst_ip']
    assert result['model_vectors_identical']
    assert not result['complete_runtime_features_identical']
    assert not result['udp_rate_rule_decisions_identical']


@pytest.mark.parametrize('kind,first,concentration', [('mixed_32',31,.8), ('spread',None,1/32), ('low_32',None,1)])
def test_existing_concentration_controls_are_retained_with_original_final_scope(kind, first, concentration):
    result = diagnostic.spoof_history_detail(list(events(kind)))
    actual = result['first_disabled_indicator']
    assert (actual['event'] if actual else None) == first
    assert result['final_visible_features']['destination_concentration'] == concentration


@pytest.mark.parametrize('invalid', ['empty', 'late', 'tcp'])
def test_invalid_diagnostic_scope_cannot_silently_support_spoof_claims(invalid):
    stream = list(events('once_32'))
    stream = [] if invalid == 'empty' else stream[::-1] if invalid == 'late' else [stream[0].model_copy(update={'protocol':6})]
    with pytest.raises(ValueError, match='timestamp-ordered UDP'):
        diagnostic.spoof_history_detail(stream)


def test_scoped_run_opens_only_exposed_spoof_report_and_predicts_only_four_fp_prefixes(monkeypatch):
    from ml.model import Model

    original_read, original_import = diagnostic.Path.read_bytes, diagnostic.importlib.import_module
    original_predict = Model.predict
    reads, imports, calls = [], [], []
    def only_spoof_read(path):
        if 'release-audit' in path.parts:
            assert path.name == 'spoofed_source_validation.json'
            reads.append(path.name)
        return original_read(path)
    def only_spoof_import(name):
        assert name == 'datasets.validate_spoofed_source'
        imports.append(name)
        return original_import(name)
    def predict(model, f):
        calls.append(f)
        return original_predict(model, f)
    monkeypatch.setattr(diagnostic.Path, 'read_bytes', only_spoof_read)
    monkeypatch.setattr(diagnostic.importlib, 'import_module', only_spoof_import)
    monkeypatch.setattr(Model, 'predict', predict)
    r = diagnostic.analyze(group='SPOOF')
    assert reads == ['spoofed_source_validation.json']
    assert imports == ['datasets.validate_spoofed_source']
    assert len(calls) == 25 + 50 + 25 + 25
    m = r['modules'][0]
    assert [row['group'] for row in r['modules']] == ['SPOOF']
    assert m['saved_counts'] == m['saved_disabled_indicator_counts'] == dict(TP=4,TN=2,FP=4,FN=0)
    assert len(m['opposite_label_overlaps']) == 3
    assert len(m['causal_histories']) == 10
    assert r['first_false_positive_sources'] == {'HYBRID':4}
    assert not any(r['policy'].values())


@pytest.mark.parametrize('mutation,message', [('label','Spoof labels'), ('history','Spoof causal history'), ('counts','predicate counts')])
def test_saved_provenance_history_and_counts_cannot_be_silently_relabelled(monkeypatch, mutation, message):
    original_read = diagnostic.Path.read_bytes
    def changed_report(path):
        raw = original_read(path)
        if path.name == 'spoofed_source_validation.json':
            r = json.loads(raw)
            if mutation == 'label':
                r['scenarios'][0]['ground_truth_forged'] = False
            elif mutation == 'history':
                r['scenarios'][0]['diagnostic_only_indicator']['first']['features']['singleton_source_fraction'] = 0
            else:
                r['diagnostic_only_indicator_counts']['FP'] = 0
            return json.dumps(r).encode()
        return raw
    monkeypatch.setattr(diagnostic.Path, 'read_bytes', changed_report)
    with pytest.raises(ValueError, match=message):
        diagnostic.analyze(group='SPOOF')


def test_wrong_model_is_rejected_before_any_evaluation_report_is_opened(tmp_path, monkeypatch):
    path = tmp_path/'artifact.json'
    path.write_bytes(b'changed model')
    assert hashlib.sha256(path.read_bytes()).hexdigest() != diagnostic.SPOOF_MODEL_SHA256
    monkeypatch.setattr(diagnostic, 'ARTIFACT', path)
    with pytest.raises(ValueError, match='unchanged frozen baseline model'):
        diagnostic.analyze(group='SPOOF')


def test_frozen_default_source_inventory_is_not_expanded_by_scoped_spoof_support():
    assert [item[0] for item in diagnostic.SOURCES] == ['UDP','C2','RECON','EXFIL','ENCRYPTED']

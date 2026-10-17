"""Previously exposed recon evidence, without inference of authorization."""
import json

import pytest

from datasets import analyze_baseline_failures as diagnostic
from datasets.validate_recon import events


@pytest.mark.parametrize('kind,interval,hosts,ports,guard,rule', [
    ('vertical', 100, 1, 32, 10, 20),
    ('horizontal', 100, 32, 1, 10, 20),
    ('mixed', 100, 16, 32, 10, 20),
    ('vertical', 500, 1, 21, 10, 20),
    ('horizontal', 2000, 6, 1, None, None),
    ('discovery', 100, 24, 1, 10, 20),
    ('monitoring', 2000, 6, 1, None, None),
    ('admin', 100, 1, 9, None, None),
    ('browsing', 1000, 3, 2, None, None),
])
def test_causal_fanout_trace_matches_existing_shapes_without_prediction(
        monkeypatch, kind, interval, hosts, ports, guard, rule):
    def forbidden(*args, **kwargs):
        pytest.fail('History diagnosis must not predict or train')
    monkeypatch.setattr('ml.model.Model.predict', forbidden)
    monkeypatch.setattr('ml.train.fit', forbidden)
    r = diagnostic.recon_history_detail(list(events(kind, interval)))
    assert r['max_destination_hosts_ten_seconds'] == hosts
    assert r['max_destination_ports_ten_seconds'] == ports
    assert (r['first_model_guard_eligible']['event'] if r['first_model_guard_eligible'] else None) == guard
    assert (r['first_rule_eligible']['event'] if r['first_rule_eligible'] else None) == rule


@pytest.mark.parametrize('kind', ['vertical', 'horizontal'])
def test_full_authorised_unauthorised_pair_is_identical_in_every_visible_representation(kind):
    positive, benign = list(events(kind, 100)), list(events(kind, 100))
    r = diagnostic.recon_pair_detail(positive, benign)
    assert r['complete_metadata_identical']
    assert r['complete_runtime_features_identical']
    assert r['complete_model_vectors_identical']
    assert r['compared_prefix_events'] == 32


def test_service_discovery_is_a_prefix_collision_not_a_complete_stream_collision():
    positive = list(events('horizontal', 100))
    benign = list(events('discovery', 100))
    r = diagnostic.recon_pair_detail(positive, benign)
    assert (r['positive_events'], r['benign_events'], r['compared_prefix_events']) == (32, 24, 24)
    assert r['metadata_prefix_identical'] and r['runtime_feature_prefix_identical']
    assert r['model_vector_prefix_identical']
    assert not r['complete_metadata_identical']
    assert not r['complete_runtime_features_identical']
    assert not r['complete_model_vectors_identical']


def test_guard_and_rule_evidence_cannot_be_borrowed_from_future_fanout():
    stream = list(events('vertical', 100))
    assert diagnostic.recon_history_detail(stream[:9])['first_model_guard_eligible'] is None
    ten = diagnostic.recon_history_detail(stream[:10])['first_model_guard_eligible']
    assert ten['event'] == 10 and ten['elapsed_seconds'] == .9
    assert ten['reference']['port_count'] == 10
    assert diagnostic.recon_history_detail(stream[:19])['first_rule_eligible'] is None
    twenty = diagnostic.recon_history_detail(stream[:20])['first_rule_eligible']
    assert twenty['event'] == 20 and twenty['elapsed_seconds'] == 1.9
    assert twenty['reference']['port_count'] == 20


@pytest.mark.parametrize('mutation', ['empty', 'late', 'udp', 'aggregate', 'multiple_sources'])
def test_history_rejects_inputs_outside_the_frozen_reference_scope(mutation):
    stream = list(events('horizontal', 100))
    if mutation == 'empty':
        stream = []
    elif mutation == 'late':
        stream.reverse()
    else:
        field = {'udp': {'protocol': 17}, 'aggregate': {'packets': 2},
                 'multiple_sources': {'src_ip': '10.0.0.11'}}[mutation]
        stream[0] = stream[0].model_copy(update=field)
    with pytest.raises(ValueError, match='ordered single-source one-packet TCP'):
        diagnostic.recon_history_detail(stream)


def test_invalid_pair_never_claims_prefix_equality():
    stream = list(events('horizontal', 100))
    for positive, benign in [(stream, []), ([], stream), (stream[:8], stream), (stream[::-1], stream)]:
        with pytest.raises(ValueError, match='aligned benign prefix'):
            diagnostic.recon_pair_detail(positive, benign)


def test_recon_scope_reads_one_exposed_report_and_predicts_only_three_recorded_fp_prefixes(monkeypatch):
    from ml.model import Model

    original_read = diagnostic.Path.read_bytes
    original_import = diagnostic.importlib.import_module
    original_predict = Model.predict
    reads, imports, predictions = [], [], []

    def read_report(path):
        if 'release-audit' in path.parts:
            assert path.name == 'recon_development.json'
            reads.append(path.name)
        return original_read(path)

    def import_generator(name):
        assert name == 'datasets.validate_recon'
        imports.append(name)
        return original_import(name)

    def predict(model, features):
        predictions.append(max(features['destination_count'], features['port_count']))
        return original_predict(model, features)

    monkeypatch.setattr(diagnostic.Path, 'read_bytes', read_report)
    monkeypatch.setattr(diagnostic.importlib, 'import_module', import_generator)
    monkeypatch.setattr(Model, 'predict', predict)
    r = diagnostic.analyze(group='RECON')
    assert reads == ['recon_development.json'] and imports == ['datasets.validate_recon']
    assert predictions == list(range(1, 11)) * 3
    assert r['first_false_positive_sources'] == {'ML': 3}
    assert len(r['modules']) == 1 and r['modules'][0]['group'] == 'RECON'
    assert len(r['modules'][0]['causal_histories']) == 11
    assert len(r['modules'][0]['paired_observability']) == 3
    assert not any(r['policy'].values())


@pytest.mark.parametrize('mutation,message', [('label', 'Recon labels'), ('history', 'Recon causal history')])
def test_changed_labels_or_saved_windows_fail_instead_of_relabelling(monkeypatch, mutation, message):
    original_read = diagnostic.Path.read_bytes

    def changed(path):
        raw = original_read(path)
        if path.name == 'recon_development.json' and 'release-audit' in path.parts:
            d = json.loads(raw)
            if mutation == 'label':
                d['scenarios'][0]['ground_truth_unauthorised_scan'] = False
            else:
                d['scenarios'][0]['max_destination_hosts_ten_seconds'] += 1
            return json.dumps(d).encode()
        return raw

    monkeypatch.setattr(diagnostic.Path, 'read_bytes', changed)
    with pytest.raises(ValueError, match=message):
        diagnostic.analyze(group='RECON')

"""Existing transfer intent collisions and causal reverse-data semantics."""
import json

import pytest

from datasets import analyze_baseline_failures as diagnostic
from datasets.validate_exfil import events


@pytest.mark.parametrize('kind,maximum,rate,first,status', [
    ('single_large', 25_000_000, 2_500_000, 1, 'reverse_unavailable'),
    ('sustained', 32_000_000, 1_200_000, 6, 'reverse_unavailable'),
    ('bidir', 32_000_000, 1_200_000, 6, 'finite_observed_ratio'),
    ('volume_only', 30_000_000, 1_500_000, 5, 'reverse_unavailable'),
    ('slow', 20_000_000, 400_000, None, 'reverse_unavailable'),
    ('small', 8_000_000, 300_000, None, 'reverse_unavailable'),
    ('inbound_heavy', 16_000_000, 600_000, None, 'finite_observed_ratio'),
])
def test_exposed_causal_windows_without_prediction(monkeypatch, kind, maximum, rate, first, status):
    def forbidden(*args, **kwargs):
        pytest.fail('Causal transfer diagnosis must not predict or train')
    monkeypatch.setattr('ml.model.Model.predict', forbidden)
    monkeypatch.setattr('ml.train.fit', forbidden)
    r = diagnostic.exfil_history_detail(list(events(kind)))
    assert r['max_source_forward_bytes_60s'] == maximum
    assert r['max_source_forward_byte_rate_10s'] == rate
    assert (r['first_volume_rule_eligible']['event'] if r['first_volume_rule_eligible'] else None) == first
    assert r['observed_ratio_statuses'] == [status]
    assert r['source_byte_window_resolution_ms'] == 1000


@pytest.mark.parametrize('kind', ['single_large', 'sustained', 'bidir', 'volume_only'])
def test_four_opposite_purpose_pairs_collide_in_raw_runtime_model_and_rule(kind):
    r = diagnostic.exfil_pair_detail(list(events(kind)), list(events(kind)))
    assert r['metadata_identical'] and r['complete_runtime_features_identical']
    assert r['model_vectors_identical'] and r['volume_rule_decisions_identical']


def test_missing_reverse_is_not_observed_zero_or_an_infinite_ratio():
    unknown = list(events('single_large'))
    observed_zero = [unknown[0].model_copy(update={'reverse_observed': True, 'reverse_bytes': 0})]
    missing = diagnostic.exfil_history_detail(unknown)['final_reference']
    zero = diagnostic.exfil_history_detail(observed_zero)['final_reference']
    assert missing['reverse_available'] == 0 and zero['reverse_available'] == 1
    assert missing['observed_byte_ratio'] is None and zero['observed_byte_ratio'] is None
    assert missing['ratio_status'] == 'reverse_unavailable'
    assert zero['ratio_status'] == 'zero_observed_reverse_bytes'
    pair = diagnostic.exfil_pair_detail(unknown, observed_zero)
    assert not pair['metadata_identical'] and not pair['complete_runtime_features_identical']
    assert not pair['model_vectors_identical']
    assert pair['volume_rule_decisions_identical']


def test_finite_observed_ratio_remains_per_event_not_lifetime_volume_ratio():
    r = diagnostic.exfil_history_detail(list(events('bidir')))
    assert r['final_reference']['observed_forward_bytes_60s'] == 32_000_000
    assert r['final_reference']['observed_byte_ratio'] == 40
    assert r['final_reference']['reverse_available'] == 1


def test_strict_volume_boundary_and_early_prefix_use_no_future_bytes():
    stream = list(events('sustained'))
    twenty = diagnostic.exfil_history_detail(stream[:5])
    assert twenty['max_source_forward_bytes_60s'] == 20_000_000
    assert twenty['first_volume_rule_eligible'] is None
    twenty_four = diagnostic.exfil_history_detail(stream[:6])['first_volume_rule_eligible']
    assert twenty_four['event'] == 6 and twenty_four['elapsed_seconds'] == 25
    assert twenty_four['reference']['observed_forward_bytes_60s'] == 24_000_000
    assert diagnostic.exfil_history_detail(list(events('slow')))['first_volume_rule_eligible'] is None


@pytest.mark.parametrize('mutation', ['empty', 'late', 'udp', 'subsecond', 'multiple_sources'])
def test_history_rejects_inputs_outside_second_aligned_reference_scope(mutation):
    stream = list(events('sustained'))
    if mutation == 'empty':
        stream = []
    elif mutation == 'late':
        stream.reverse()
    else:
        field = {'udp': {'protocol': 17}, 'subsecond': {'timestamp': stream[0].timestamp + .5},
                 'multiple_sources': {'src_ip': '10.0.0.11'}}[mutation]
        stream[0] = stream[0].model_copy(update=field)
    with pytest.raises(ValueError, match='ordered single-source second-aligned TCP'):
        diagnostic.exfil_history_detail(stream)


def test_invalid_complete_pairs_cannot_claim_equivalence():
    stream = list(events('sustained'))
    for positive, benign in [(stream, []), ([], stream), (stream[:3], stream), (stream[::-1], stream)]:
        with pytest.raises(ValueError, match='nonempty aligned ordered TCP'):
            diagnostic.exfil_pair_detail(positive, benign)


def test_exfil_scope_reads_one_old_report_and_predicts_only_four_fp_prefixes(monkeypatch):
    from ml.model import Model

    original_read = diagnostic.Path.read_bytes
    original_import = diagnostic.importlib.import_module
    original_predict = Model.predict
    reads, imports, calls = [], [], []

    def read(path):
        if 'release-audit' in path.parts:
            assert path.name == 'exfil_development.json'
            reads.append(path.name)
        return original_read(path)

    def import_generator(name):
        assert name == 'datasets.validate_exfil'
        imports.append(name)
        return original_import(name)

    def predict(model, features):
        calls.append(features)
        return original_predict(model, features)

    monkeypatch.setattr(diagnostic.Path, 'read_bytes', read)
    monkeypatch.setattr(diagnostic.importlib, 'import_module', import_generator)
    monkeypatch.setattr(Model, 'predict', predict)
    r = diagnostic.analyze(group='EXFIL')
    assert reads == ['exfil_development.json'] and imports == ['datasets.validate_exfil']
    assert len(calls) == 6 + 1 + 1 + 5
    assert r['first_false_positive_sources'] == {'RULE': 3, 'ML': 1}
    m = r['modules'][0]
    assert len(r['modules']) == 1 and m['group'] == 'EXFIL'
    assert len(m['causal_histories']) == 11 and len(m['paired_observability']) == 4
    for failure in m['failures']:
        if failure['verdict'] == 'FP':
            wording = failure['first_alert']['supporting_evidence']
            assert 'behavior consistent with possible exfiltration' in wording
            assert 'content and intent unverified' in wording
    assert not any(r['policy'].values())


@pytest.mark.parametrize('mutation,message', [
    ('label', 'Exfil labels'), ('history', 'Exfil causal history'),
    ('wording', 'supporting evidence'),
])
def test_changed_source_labels_windows_or_wording_refuse_relabelling(monkeypatch, mutation, message):
    original_read = diagnostic.Path.read_bytes

    def changed(path):
        raw = original_read(path)
        if path.name == 'exfil_development.json' and 'release-audit' in path.parts:
            r = json.loads(raw)
            if mutation == 'label':
                r['scenarios'][0]['ground_truth_exfil_like'] = False
            elif mutation == 'history':
                r['scenarios'][0]['final_reference']['observed_forward_bytes_60s'] += 1
            else:
                row = next(x for x in r['scenarios'] if x['verdict'] == 'FP')
                row['first_alert']['supporting_evidence'] = 'unverified changed text'
            return json.dumps(r).encode()
        return raw

    monkeypatch.setattr(diagnostic.Path, 'read_bytes', changed)
    with pytest.raises(ValueError, match=message):
        diagnostic.analyze(group='EXFIL')

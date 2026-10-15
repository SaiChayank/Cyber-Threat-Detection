"""Exact, first-label-only DGA feature and rule regressions."""
import math

import pytest

from datasets.compare_dga_rules import main as compare_main
from detection.dga_rules import conservative_rule, validation_rule
from features.extractor import FeatureExtractor, dga_lexical_features
from ml.dga import lexical_features
from schemas.traffic_event import TrafficEvent


def test_dga_features_use_only_the_visible_first_label():
    first = dga_lexical_features('AbAbA.example.org.')
    second = dga_lexical_features('ababa.other.co.uk')
    assert first == second
    assert first['domain_label_length'] == 5
    assert first['domain_entropy'] == pytest.approx(-(3 / 5) * math.log2(3 / 5)
                                                    - (2 / 5) * math.log2(2 / 5))
    assert first['domain_digit_ratio'] == 0
    assert first['bigram_surprise'] == 1
    assert first['domain_vowel_ratio'] == .6
    assert first['domain_consonant_run'] == .2


def test_dga_rule_features_equal_runtime_extractor_and_candidate_lexical_path():
    name = 'xqjmtvkp.example.org'
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17, dns_name=name)
    runtime = FeatureExtractor().update(event)
    direct = dga_lexical_features(name)
    candidate = lexical_features('xqjmtvkp')
    for key in direct:
        assert runtime[key] == direct[key]
    assert direct['domain_entropy'] == candidate['entropy']
    assert direct['domain_digit_ratio'] == candidate['digit_ratio']
    assert direct['domain_vowel_ratio'] == candidate['vowel_ratio']
    assert direct['domain_consonant_run'] == candidate['consonant_run']
    assert not conservative_rule(runtime)
    assert validation_rule(runtime)


def test_validation_rule_boundaries_and_readable_name():
    assert not validation_rule(dga_lexical_features('xqjmtvk.example'))  # Seven characters.
    assert validation_rule(dga_lexical_features('xqjmtvkp.example'))
    assert not validation_rule(dga_lexical_features('vaxvacationaccess.example'))
    assert not conservative_rule(dga_lexical_features('xqjmtvkp.example'))
    assert conservative_rule(dga_lexical_features('q7x9k2z4m6b8v1j3p5d0r2s4w6.example'))


def test_exact_character_composition_matches_candidate_and_rule_paths():
    numeric = lexical_features('a1b2--cd')
    assert numeric == pytest.approx(dict(log_length=math.log(9), entropy=2.75,
        digit_ratio=2 / 8, vowel_ratio=1 / 8, hyphen_ratio=2 / 8,
        unique_ratio=7 / 8, consonant_run=2 / 8, digit_run=1 / 8,
        digit_transitions=4 / 8, repeat_ratio=1 / 8))
    rule = dga_lexical_features('A1B2--CD.example.')
    assert rule == dict(domain_entropy=2.75, domain_label_length=8,
        domain_digit_ratio=2 / 8, bigram_surprise=1,
        domain_vowel_ratio=1 / 8, domain_consonant_run=2 / 8)


def test_bigram_surprise_normalizes_by_visible_pair_count():
    assert dga_lexical_features('the.example')['bigram_surprise'] == 0
    assert dga_lexical_features('thx.example')['bigram_surprise'] == .5
    assert dga_lexical_features('x.example')['bigram_surprise'] == 0
    assert dga_lexical_features('')['domain_entropy'] == 0


@pytest.mark.parametrize('key,value', [
    ('domain_label_length', 7), ('domain_label_length', 16),
    ('domain_entropy', 2.499999), ('bigram_surprise', .899999),
    ('domain_vowel_ratio', .200001), ('domain_consonant_run', .349999),
])
def test_short_validation_rule_exact_boundaries(key, value):
    features = dict(domain_label_length=8, domain_entropy=2.5,
        bigram_surprise=.9, domain_vowel_ratio=.2, domain_consonant_run=.35)
    assert validation_rule(features)
    assert not validation_rule(features | {key: value})


@pytest.mark.parametrize('key,value', [
    ('domain_label_length', 15), ('domain_entropy', 3.399999),
    ('bigram_surprise', .799999), ('domain_vowel_ratio', .300001),
])
def test_long_validation_rule_exact_boundaries(key, value):
    features = dict(domain_label_length=16, domain_entropy=3.4,
        bigram_surprise=.8, domain_vowel_ratio=.3, domain_consonant_run=0)
    assert validation_rule(features)
    assert not validation_rule(features | {key: value})


def test_dns_lexical_features_are_independent_of_peer_history_and_future_events():
    def event(timestamp, name):
        return TrafficEvent(timestamp=timestamp, src_ip='192.0.2.1',
            dst_ip='192.0.2.53', dst_port=53, protocol=17, dns_name=name)
    extractor = FeatureExtractor()
    name = 'xqjmtvkp.example'
    before = extractor.update(event(1700000000000, name))
    extractor.update(event(1700000001000, 'telemetry.example'))
    after = extractor.update(event(1700000002000, name))
    for key, value in dga_lexical_features(name).items():
        assert before[key] == after[key] == value


def test_comparison_refuses_to_overwrite_frozen_evidence_before_loading_data(tmp_path, monkeypatch):
    import datasets.compare_dga_rules as comparison
    path = tmp_path / 'frozen.json'
    path.write_text('frozen evidence', encoding='utf-8')
    def forbidden():
        pytest.fail('Existing output must be rejected before model/data loading')
    monkeypatch.setattr(comparison, 'DgaModel', forbidden)
    monkeypatch.setattr(comparison, 'load_data', forbidden)
    with pytest.raises(FileExistsError, match='Preserve existing DGA evidence'):
        compare_main(path)
    assert path.read_text(encoding='utf-8') == 'frozen evidence'


def test_comparison_rejects_changed_partition_before_scoring(tmp_path, monkeypatch):
    import datasets.compare_dga_rules as comparison
    from types import SimpleNamespace
    def forbidden_score(*args):
        pytest.fail('A changed frozen partition must never be scored')
    monkeypatch.setattr(comparison, 'DgaModel', lambda: SimpleNamespace(
        enabled=False, _uncached_score=forbidden_score))
    monkeypatch.setattr(comparison, 'load_data', lambda: (
        {'train': [('changedlabel', 0, 'legit')], 'validation': []}, {}, {}))
    path = tmp_path / 'new-report.json'
    with pytest.raises(ValueError, match='Frozen DGA development partition changed'):
        compare_main(path)
    assert not path.exists()

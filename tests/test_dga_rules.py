"""Exact, first-label-only DGA feature and rule regressions."""
import math

import pytest

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

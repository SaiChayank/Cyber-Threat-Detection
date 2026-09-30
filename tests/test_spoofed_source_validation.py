"""Integrity checks for the controlled spoofed-source visibility audit."""
import pytest

from datasets.validate_spoofed_source import score


@pytest.mark.parametrize('attack,benign,kind', [
    ('forged_32_once', 'genuine_distributed_32', 'once_32'),
    ('forged_64_once', 'flash_crowd_64', 'once_64'),
    ('forged_32_repeat', 'genuine_repeat_32', 'repeat_32'),
])
def test_matched_provenance_pairs_have_identical_visible_streams(attack, benign, kind):
    positive = score(attack, True, kind)
    negative = score(benign, False, kind)
    assert positive['observed_stream_sha256'] == negative['observed_stream_sha256']
    assert positive['final_visible_features'] == negative['final_visible_features']
    assert positive['diagnostic_only_indicator']['first']['features'] == negative['diagnostic_only_indicator']['first']['features']
    assert positive['diagnostic_only_indicator']['verdict'] == 'TP'
    assert negative['diagnostic_only_indicator']['verdict'] == 'FP'


def test_singleton_fraction_uses_only_observations_seen_so_far():
    result = score('forged_32_repeat', True, 'repeat_32')
    first = result['diagnostic_only_indicator']['first']
    assert first['event'] == 25 < result['events']
    assert first['features']['singleton_source_fraction'] == 1
    assert result['final_visible_features']['singleton_source_fraction'] == 0
    assert first['wording'] == 'consistent with suspected spoofed-source flood'


def test_spread_final_concentration_includes_other_destinations():
    result = score('authorised_spread', False, 'spread')
    assert result['final_visible_features']['target_packet_rate'] == 40
    assert result['final_visible_features']['destination_concentration'] == pytest.approx(1 / 32)
    assert result['existing_ddos']['verdict'] == 'TN'
    assert result['diagnostic_only_indicator']['verdict'] == 'TN'


def test_runtime_alert_does_not_claim_proven_source_forgery():
    result = score('forged_32_once', True, 'once_32')
    wording = result['existing_ddos']['first']['wording'].lower()
    assert 'forged' not in wording
    assert 'spoofed' not in wording
    assert 'cannot verify' in wording

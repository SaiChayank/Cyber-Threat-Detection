"""Integrity checks for causal C2 development scenarios."""
import pytest

from datasets.validate_c2_beacon import events, score


@pytest.mark.parametrize('kind,interval', [
    ('fixed_2_5', 2.5), ('fixed_6', 6), ('fixed_12', 12),
    ('fixed_20', 20), ('fixed_60', 60),
])
def test_fixed_intervals_are_exact_and_not_demo_specific(kind, interval):
    stream = list(events(kind, 130))
    assert len(stream) == 32
    assert [(right.timestamp - left.timestamp) / 1000
            for left, right in zip(stream, stream[1:])] == [interval] * 31


def test_rotating_and_jittered_cases_have_distinct_causal_patterns():
    rotating = list(events('rotate_12', 130))
    jittered = list(events('jitter_6', 130))
    assert len({str(event.dst_ip) for event in rotating}) == 2
    assert [(right.timestamp - left.timestamp) / 1000
            for left, right in zip(rotating, rotating[1:])] == [12] * 31
    assert set((right.timestamp - left.timestamp) / 1000
               for left, right in zip(jittered, jittered[1:])) == {5.4, 6.6}


def test_short_periodic_stops_before_eight_peer_observations():
    assert len(list(events('short_6', 130))) == 7


def test_health_check_and_demo_beacon_are_observationally_identical():
    beacon = score('beacon_fixed_2_5', True, 'fixed_2_5', 130)
    health = score('health_check_2_5', False, 'fixed_2_5', 130)
    assert beacon['observed_stream_sha256'] == health['observed_stream_sha256']
    assert beacon['first_alert']['event'] == health['first_alert']['event'] == 8
    assert beacon['verdict'] == 'TP'
    assert health['verdict'] == 'FP'


def test_slow_and_rotating_peer_history_is_limited_to_sixty_seconds():
    slow = score('beacon_fixed_20', True, 'fixed_20', 130)
    rotating = score('beacon_rotate_12', True, 'rotate_12', 130)
    assert slow['max_peer_history_count'] == 4
    assert rotating['max_peer_history_count'] == 3
    assert rotating['final_audited_features']['source_destination_count_last_60s'] == 2
    assert rotating['final_audited_features']['destination_count_last_10s'] == 1


def test_jittered_beacon_uses_model_at_current_cv_and_history():
    jitter = score('beacon_jitter_6', True, 'jitter_6', 130)
    first = jitter['first_alert']
    assert first['event'] == 8
    assert first['detection_source'] == 'ML'
    assert first['audited_features']['iat_cv'] > .05
    assert first['audited_features']['peer_history_count'] == 8

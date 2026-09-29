"""Regressions for complete packet totals in bounded streaming state."""
import math
import random
from collections import Counter

import pytest

from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from features.rate_window import RateWindow
from schemas.traffic_event import TrafficEvent


def event(offset=0, source='192.0.2.1', packets=1, size=60):
    return TrafficEvent(timestamp=1700000000000 + offset, src_ip=source,
                        dst_ip='198.51.100.1', protocol=17, dst_port=443,
                        packets=packets, bytes=size)


def test_raw_packet_flood_is_not_capped_by_record_capacity():
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    first_alert = None
    for i in range(12000):
        alerts = pipeline.process(event(i / 2))
        if alerts and first_alert is None:
            first_alert = (i, alerts[0])
    assert first_alert is not None
    index, alert = first_alert
    assert index == 9999 and index < 11999
    assert alert.threat_class == 'DDOS' and alert.detection_source == 'RULE'
    assert alert.raw_evidence_metrics['packet_rate'] == 1000
    assert alert.raw_evidence_metrics['rate_window_resolution_ms'] == 1000
    assert pipeline.extractor.global_rates.packets == 12000
    assert len(pipeline.extractor.global_rates.buckets) <= 11


def test_flow_summary_and_individual_packets_preserve_totals():
    summary, packets = RateWindow(), RateWindow()
    expected = summary.update(event(packets=5000, size=300000))
    for _ in range(5000):
        actual = packets.update(event())
    assert actual['packet_rate'] == expected['packet_rate'] == 500
    assert actual['byte_rate'] == expected['byte_rate'] == 30000
    assert actual['source_entropy'] == pytest.approx(0, abs=1e-10)


def test_bucket_rates_and_entropy_match_independent_reference():
    rng = random.Random(26145)
    window = RateWindow()
    seen, offset = [], 0
    for _ in range(300):
        offset += rng.randint(0, 400)
        sample = event(offset, source=f'192.0.2.{rng.randint(1, 8)}',
                       packets=rng.randint(1, 20), size=rng.randint(0, 4000))
        seen.append(sample)
        active = [e for e in seen if int(e.timestamp // 1000) >= int(sample.timestamp // 1000) - 10]
        counts = Counter(str(e.src_ip) for e in active)
        expected_entropy = -sum(n / len(active) * math.log2(n / len(active)) for n in counts.values())
        actual = window.update(sample)
        assert actual['packet_rate'] == sum(e.packets for e in active) / 10
        assert actual['byte_rate'] == sum(e.bytes for e in active) / 10
        assert actual['source_entropy'] == pytest.approx(expected_entropy, abs=1e-10)
        assert not actual['source_entropy_partial']
        assert len(window.buckets) <= 11


def test_time_resolution_is_disclosed_and_expired_packets_are_removed():
    window = RateWindow()
    window.update(event(900, packets=100))
    boundary = window.update(event(10901))
    assert boundary['packet_rate'] == 10.1  # Partial oldest second is retained.
    assert boundary['rate_window_seconds'] == 10
    assert boundary['rate_window_resolution_ms'] == 1000
    expired = window.update(event(11000))
    assert expired['packet_rate'] == .2
    reset = window.update(event(100000))
    assert reset['packet_rate'] == .1 and window.observations == 1
    assert reset['source_entropy'] == pytest.approx(0, abs=1e-10)


def test_source_identity_overflow_preserves_rates_and_discloses_entropy_limit():
    window = RateWindow(max_sources=2)
    for i in range(1, 101):
        result = window.update(event(i, source=f'192.0.2.{i}', packets=10))
    assert result['packet_rate'] == 100
    assert result['byte_rate'] == 600
    assert result['source_entropy_partial']
    assert len(window.sources) == 3  # Two exact identities plus one overflow group.
    assert all(len(bucket.sources) <= 3 for bucket in window.buckets)
    assert result['source_entropy'] < math.log2(100)
    recovered = window.update(event(20000, source='192.0.2.200'))
    assert not recovered['source_entropy_partial']
    assert recovered['packet_rate'] == 1 / 10


def test_late_event_cannot_change_global_rate_state():
    extractor = FeatureExtractor()
    extractor.update(event(2000, packets=100))
    assert extractor.update(event(1000, packets=1000000)) is None
    assert extractor.global_rates.packets == 100
    assert extractor.late_events == 1


def test_overflow_identity_stays_grouped_until_its_observations_expire():
    window = RateWindow(max_sources=1)
    window.update(event(0, source='192.0.2.1'))
    window.update(event(9500, source='192.0.2.2'))
    result = window.update(event(11000, source='192.0.2.2'))
    # The first tracked source expired. Splitting the remaining source between a
    # new identity and overflow would manufacture entropy for one real source.
    assert result['source_entropy'] == pytest.approx(0, abs=1e-10)
    assert len(window.sources) == 1 and window.sources[None] == 2
    assert result['source_entropy_partial']


def test_rate_window_rejects_empty_source_capacity():
    with pytest.raises(ValueError):
        RateWindow(max_sources=0)

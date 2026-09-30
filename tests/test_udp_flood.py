"""UDP-only regressions for causal, destination-scoped flood evidence."""
import math

import pytest

from detection.pipeline import Pipeline
from features.rate_window import RateWindow
from schemas.traffic_event import TrafficEvent


START = 1_700_000_000_000.0
VICTIM = '198.51.100.10'


def udp_event(index, *, source='192.0.2.1', target=VICTIM, packets=1,
              size=64, offset_ms=0):
    return TrafficEvent(timestamp=START + offset_ms + index * 100,
                        src_ip=source, dst_ip=target, protocol=17,
                        src_port=49152, dst_port=9000,
                        packets=packets, bytes=packets * size)


def ddos_alerts(pipeline, events):
    return [(index, alert) for index, event in enumerate(events, start=1)
            for alert in pipeline.process(event) if alert.threat_class == 'DDOS']


def test_raw_udp_packet_size_and_source_entropy_are_exact():
    window = RateWindow(source_weight_packets=True)
    window.update(udp_event(0, source='192.0.2.1', size=64))
    result = window.update(udp_event(1, source='192.0.2.2', size=1200))
    assert result['packet_rate'] == .2
    assert result['byte_rate'] == 126.4
    assert result['source_entropy'] == pytest.approx(1)
    assert result['mean_packet_bytes'] == 632
    assert result['packet_size_cv'] == pytest.approx(568 / 632)
    assert result['packet_size_basis'] == 'packet_exact'


def test_flow_summary_size_variation_is_marked_as_proxy_and_expires():
    window = RateWindow(source_weight_packets=True)
    window.update(udp_event(0, packets=100, size=64))
    result = window.update(udp_event(1, packets=100, size=1200))
    assert result['packet_rate'] == 20
    assert result['mean_packet_bytes'] == 632
    assert result['packet_size_cv'] == pytest.approx(568 / 632)
    assert result['packet_size_basis'] == 'summary_mean_proxy'
    fresh = window.update(udp_event(0, packets=50, size=256, offset_ms=11_000))
    assert fresh['packet_rate'] == 5
    assert fresh['mean_packet_bytes'] == 256
    assert fresh['packet_size_cv'] == 0
    assert fresh['packet_size_basis'] == 'summary_mean_proxy'


def test_udp_flood_alert_is_incremental_and_uses_target_evidence():
    pipeline = Pipeline()
    events = [udp_event(index, source=f'192.0.2.{index + 1}',
                        packets=4000, size=1200) for index in range(4)]
    alerts = ddos_alerts(pipeline, events)
    assert alerts and alerts[0][0] == 3 < len(events)
    evidence = alerts[0][1].raw_evidence_metrics
    assert evidence['packet_rate'] == 1200
    assert evidence['byte_rate'] == 1_440_000
    assert evidence['source_count_lower_bound'] == 3
    assert evidence['source_entropy'] == pytest.approx(math.log2(3))
    assert evidence['destination_concentration'] == 1
    assert evidence['mean_packet_bytes'] == 1200
    assert evidence['packet_size_cv'] == 0
    assert evidence['packet_size_basis'] == 'summary_mean_proxy'
    assert evidence['udp_target'] == 'destination_udp'
    assert 'cannot verify reflection or amplification' in alerts[0][1].supporting_evidence


def test_spread_udp_volume_cannot_trigger_target_alert_even_from_model():
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('DDOS', .99)
    events = [udp_event(index, target=f'198.51.100.{index + 10}',
                        packets=800, size=1200) for index in range(20)]
    assert not ddos_alerts(pipeline, events)
    assert pipeline.extractor.global_rates.packets == 16_000
    assert all(window.packets == 800 for window in pipeline.extractor.udp_targets.values())


def test_low_rate_udp_cannot_trigger_from_synthetic_model_posterior():
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('DDOS', .99)
    events = [udp_event(index, packets=100, size=80) for index in range(10)]
    assert not ddos_alerts(pipeline, events)
    assert pipeline.extractor.udp_targets[VICTIM].packets == 1000

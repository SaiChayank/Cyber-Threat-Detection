"""SYN-only regressions for destination-scoped packet accounting."""
import math

import pytest

from detection.pipeline import Pipeline
from features.rate_window import RateWindow
from ingest.metadata import from_packet
from schemas.flow_record import FlowRecord
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def tcp_event(index, *, source='192.0.2.1', target='198.51.100.10',
              packets=1, syn=False, offset_ms=0):
    return TrafficEvent(timestamp=1_700_000_000_000 + offset_ms + index * 100,
                        src_ip=source, dst_ip=target, protocol=6, dst_port=443,
                        packets=packets, bytes=packets * 60, syn=syn,
                        syn_packets=packets if syn else 0)


def ddos_alerts(pipeline, events):
    return [(index, alert) for index, event in enumerate(events, start=1)
            for alert in pipeline.process(event) if alert.threat_class == 'DDOS']


def test_packet_adapter_counts_initial_syn_but_not_syn_ack_or_aggregate_or_flag():
    flow = FlowRecord(flow_id='f', src_ip='192.0.2.1', dst_ip='198.51.100.10',
                      src_port=49152, dst_port=443, protocol=6,
                      timestamp_start=START, timestamp_end=START,
                      packets_forward=1, bytes_forward=40, tcp_flags_forward=0x02)
    assert from_packet(flow).syn_packets == 1
    flow.tcp_flags_forward = 0x12
    assert from_packet(flow).syn_packets == 0
    flow.packets_forward = 4000
    assert from_packet(flow).syn_packets is None


def test_syn_packet_count_cannot_exceed_observed_packets():
    payload = tcp_event(0, packets=1, syn=True).model_dump()
    payload['syn_packets'] = 2
    with pytest.raises(ValueError, match='syn_packets'):
        TrafficEvent(**payload)


def test_destination_syn_fraction_uses_declared_packet_counts():
    window = RateWindow(source_weight_packets=True)
    window.update(tcp_event(0, source='192.0.2.1', packets=100, syn=True))
    result = window.update(tcp_event(1, source='192.0.2.2', packets=100, syn=False))
    assert result['packet_rate'] == 20
    assert result['syn_fraction'] == .5
    assert result['source_entropy'] == pytest.approx(1)
    assert result['source_count_lower_bound'] == 2
    assert result['syn_fraction_basis'] == 'declared_summary_counts'


def test_raw_syn_entropy_matches_32_balanced_sources():
    window = RateWindow(source_weight_packets=True)
    for index in range(32):
        result = window.update(tcp_event(index, source=f'192.0.2.{index + 1}', syn=True))
    assert result['syn_fraction'] == 1
    assert result['source_entropy'] == pytest.approx(math.log2(32))
    assert result['source_count_lower_bound'] == 32
    assert not result['source_entropy_partial']
    assert result['syn_fraction_basis'] == 'packet_exact'


def test_syn_source_overflow_keeps_packet_rate_and_marks_entropy_partial():
    window = RateWindow(max_sources=2, source_weight_packets=True)
    for index in range(3):
        result = window.update(tcp_event(index, source=f'192.0.2.{index + 1}',
                                         packets=100, syn=True))
    assert result['packet_rate'] == 30
    assert result['syn_fraction'] == 1
    assert result['source_count_lower_bound'] == 3
    assert result['source_entropy_partial']


def test_non_tcp_metadata_cannot_contribute_to_syn_packet_count():
    event = tcp_event(0, packets=4000, syn=True).model_copy(update={'protocol': 17})
    window = RateWindow(source_weight_packets=True)
    result = window.update(event)
    assert result['packet_rate'] == 400
    assert result['syn_fraction'] == 0


def test_unknown_summary_syn_share_expires_without_poisoning_new_packets():
    window = RateWindow(source_weight_packets=True)
    unknown = tcp_event(0, packets=4000, syn=True).model_copy(
        update={'syn_packets': None})
    assert window.update(unknown)['syn_fraction'] is None
    current = window.update(tcp_event(110, syn=True))
    assert current['syn_fraction'] == 1
    assert current['syn_fraction_basis'] == 'packet_exact'


def test_high_rate_established_tcp_does_not_become_ddos():
    pipeline = Pipeline()
    events = [tcp_event(i, packets=4000, syn=False) for i in range(4)]
    assert not ddos_alerts(pipeline, events)
    assert pipeline.extractor.global_rates.packets == 16000


def test_cumulative_syn_flag_cannot_pretend_every_summary_packet_was_syn():
    pipeline = Pipeline()
    events = [tcp_event(i, packets=4000, syn=True).model_copy(
        update={'syn_packets': 40}) for i in range(4)]
    assert not ddos_alerts(pipeline, events)
    assert pipeline.extractor.syn_targets['198.51.100.10'].syn_packets == 160
    unknown = [tcp_event(i, packets=4000, syn=True).model_copy(
        update={'syn_packets': None}) for i in range(4)]
    assert not ddos_alerts(Pipeline(), unknown)


def test_syn_flood_alert_is_incremental_and_has_target_evidence():
    pipeline = Pipeline()
    events = [tcp_event(i, packets=4000, syn=True) for i in range(4)]
    alerts = ddos_alerts(pipeline, events)
    assert alerts and alerts[0][0] == 3 < len(events)
    evidence = alerts[0][1].raw_evidence_metrics
    assert evidence['packet_rate'] == 1200
    assert evidence['syn_fraction'] == 1
    assert evidence['source_entropy'] == pytest.approx(0)
    assert evidence['source_count_lower_bound'] == 1
    assert evidence['syn_fraction_basis'] == 'declared_summary_counts'
    assert evidence['rate_window_resolution_ms'] == 1000


def test_unrelated_target_rate_cannot_promote_sparse_syns():
    pipeline = Pipeline()
    events = [tcp_event(i, target='198.51.100.11', packets=4000) for i in range(4)]
    events += [tcp_event(4, target='198.51.100.10', syn=True)]
    assert not ddos_alerts(pipeline, events)
    assert pipeline.extractor.global_rates.packets == 16001

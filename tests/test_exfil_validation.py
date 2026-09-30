"""Exfil-like volume, reverse-availability and evidence regressions."""
import pytest

from datasets.validate_exfil import high_flow_count_stress, score
from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from schemas.traffic_event import TrafficEvent


START = 1_700_000_000_000.0


def transfer(*, timestamp=START, source='10.0.0.10', byte_count=25_000_000,
             reverse_bytes=None):
    return TrafficEvent(timestamp=timestamp, src_ip=source,
                        dst_ip='198.51.100.20', src_port=49152, dst_port=443,
                        protocol=6, packets=100, bytes=byte_count,
                        reverse_observed=reverse_bytes is not None,
                        reverse_bytes=reverse_bytes)


def exfil_alert(event):
    return next(alert for alert in Pipeline().process(event)
                if alert.threat_class == 'DATA_EXFILTRATION')


def test_missing_reverse_stays_unavailable_and_wording_is_qualified():
    alert = exfil_alert(transfer())
    evidence = alert.raw_evidence_metrics
    assert evidence['egress_bytes'] == 25_000_000
    assert evidence['source_forward_byte_rate_10s'] == 2_500_000
    assert evidence['observed_byte_ratio'] is None
    assert evidence['reverse_available'] == 0
    assert evidence['observed_byte_ratio_status'] == 'reverse_unavailable'
    assert 'reverse traffic unavailable: volume-only suspicion' in alert.supporting_evidence
    assert 'behavior consistent with possible exfiltration' in alert.supporting_evidence
    assert 'content and intent unverified' in alert.supporting_evidence
    assert 'proven stolen' not in alert.supporting_evidence


def test_explicit_zero_reverse_is_available_but_finite_ratio_is_undefined():
    event = transfer(reverse_bytes=0)
    features = FeatureExtractor().update(event)
    assert features['reverse_available'] == 1
    assert features['observed_byte_ratio'] is None
    assert features['observed_byte_ratio_status'] == 'zero_observed_reverse_bytes'
    alert = exfil_alert(event)
    assert alert.raw_evidence_metrics['reverse_available'] == 1
    assert alert.raw_evidence_metrics['observed_byte_ratio'] is None
    assert 'finite byte ratio undefined' in alert.supporting_evidence
    assert 'reverse traffic unavailable' not in alert.supporting_evidence


def test_positive_observed_reverse_has_exact_ratio():
    alert = exfil_alert(transfer(reverse_bytes=5_000_000))
    assert alert.raw_evidence_metrics['observed_byte_ratio'] == 5
    assert alert.raw_evidence_metrics['observed_byte_ratio_status'] == 'finite_observed_ratio'
    assert alert.raw_evidence_metrics['reverse_available'] == 1


def test_source_forward_window_expires_and_does_not_mix_sources():
    extractor = FeatureExtractor()
    first = extractor.update(transfer(byte_count=4_000_000))
    extractor.update(transfer(timestamp=START + 1000, source='10.0.0.11', byte_count=10_000_000))
    second = extractor.update(transfer(timestamp=START + 2000, byte_count=4_000_000))
    assert first['source_forward_bytes_60s'] == 4_000_000
    assert second['source_forward_bytes_60s'] == 8_000_000
    assert second['source_forward_byte_rate_10s'] == 800_000
    expired = extractor.update(transfer(timestamp=START + 63_000, byte_count=1_000_000))
    assert expired['source_forward_bytes_60s'] == 1_000_000
    assert expired['source_forward_byte_rate_10s'] == 100_000


def test_source_byte_windows_follow_bounded_source_eviction():
    extractor = FeatureExtractor(max_sources=2, max_events=3)
    extractor.update(transfer(byte_count=1_000_000))
    extractor.update(transfer(timestamp=START + 1000, source='10.0.0.11', byte_count=1_000_000))
    extractor.update(transfer(timestamp=START + 2000, source='10.0.0.12', byte_count=1_000_000))
    assert len(extractor.source_byte_windows) == 2
    assert '10.0.0.10' not in extractor.source_byte_windows
    returned = extractor.update(transfer(timestamp=START + 3000, byte_count=1_000_000))
    assert returned['source_forward_bytes_60s'] == 1_000_000
    assert len(extractor.source_byte_windows) == 2


def test_source_byte_window_uses_at_most_61_second_buckets():
    extractor = FeatureExtractor()
    for second in range(120):
        extractor.update(transfer(timestamp=START + second * 1000, byte_count=1_000))
    assert len(extractor.source_byte_windows['10.0.0.10'].buckets) == 61


def test_high_flow_count_is_not_capped_by_512_event_history():
    stress = high_flow_count_stress()
    assert stress['observed_forward_bytes'] == 25_000_000
    assert stress['bounded_source_history_bytes'] == 12_800_000
    first = stress['first_alert']
    assert first['event'] == 801 < stress['events']
    assert first['evidence']['egress_bytes'] == 20_025_000
    assert first['evidence']['source_forward_byte_rate_10s'] == 502_500


@pytest.mark.parametrize('positive,benign,kind', [
    ('large_one_way', 'legitimate_large_upload', 'single_large'),
    ('sustained_one_way', 'cloud_backup', 'sustained'),
    ('sustained_observed_bidir', 'synchronization', 'bidir'),
    ('volume_only_one_way', 'replication_deployment', 'volume_only'),
])
def test_benign_business_purpose_is_not_visible_in_metadata(positive, benign, kind):
    threat = score(positive, True, kind)
    authorised = score(benign, False, kind)
    assert threat['observed_stream_sha256'] == authorised['observed_stream_sha256']
    assert threat['verdict'] == 'TP'
    assert authorised['verdict'] == 'FP'

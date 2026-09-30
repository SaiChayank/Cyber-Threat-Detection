"""DNS-only candidate regressions; deployed behavior stays disabled by default."""
import pytest

from datasets.dns_tunnel_development import SCENARIOS, events
from detection.dns_tunnel_candidate import candidate_reason
from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from replay.scenarios import scenario


def _spec(name):
    return next(spec for spec in SCENARIOS if spec[0] == name)


def _tunnel_alerts(pipeline, sequence):
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    return [(index, alert) for index, event in enumerate(sequence, start=1)
            for alert in pipeline.process(event) if alert.threat_class == 'DNS_TUNNELLING']


def test_complete_long_a_features_are_causal_and_trigger_incrementally():
    extractor = FeatureExtractor()
    sequence = list(events(_spec('train_long_a')))
    for index, event in enumerate(sequence[:5], start=1):
        features = extractor.update(event)
        assert features['dns_query_visible'] == 1
        assert features['dns_base_queries_10s'] == index
        assert features['dns_base_unique_ratio_10s'] == 1
        assert features['dns_encoded_max_label_length'] == 58
        assert candidate_reason(features) == ('repeated_long_encoded_label' if index == 5 else None)
    alerts = _tunnel_alerts(Pipeline(dns_tunnel_candidate=True), sequence)
    assert alerts and alerts[0][0] == 5 < len(sequence)
    evidence = alerts[0][1].raw_evidence_metrics
    assert evidence['dns_candidate_pattern'] == 'repeated_long_encoded_label'
    assert evidence['dns_base_queries_10s'] == 5
    assert alerts[0][1].confidence_score == .8


def test_source_history_excludes_other_sources_old_queries_and_repeated_names():
    sequence = list(events(_spec('train_long_a')))
    extractor = FeatureExtractor()
    for event in sequence[:4]:
        extractor.update(event)
    other = sequence[4].model_copy(update={'src_ip': '192.0.2.11'})
    assert extractor.update(other)['dns_base_queries_10s'] == 1
    stale = sequence[4].model_copy(update={'timestamp': sequence[4].timestamp + 11_000})
    features = extractor.update(stale)
    assert features['dns_base_queries_10s'] == 1
    assert candidate_reason(features) is None
    repeated = [sequence[0].model_copy(update={'timestamp': sequence[0].timestamp + 30_000 + i * 100,
                                               'dns_name': sequence[0].dns_name}) for i in range(7)]
    for event in repeated:
        features = extractor.update(event)
    assert features['dns_base_queries_10s'] == 7
    assert features['dns_base_unique_ratio_10s'] == pytest.approx(1 / 7)
    assert candidate_reason(features) is None


@pytest.mark.parametrize('name', ['train_long_a', 'train_long_aaaa', 'train_long_txt',
                                  'train_long_null', 'train_multi_a'])
def test_training_attack_patterns_alert_before_completion(name):
    alerts = _tunnel_alerts(Pipeline(dns_tunnel_candidate=True), list(events(_spec(name))))
    assert alerts and alerts[0][0] < 12


@pytest.mark.parametrize('name', ['train_cdn', 'train_telemetry', 'train_discovery',
                                  'train_txt', 'train_machine'])
def test_training_benign_counterexamples_do_not_alert(name):
    assert not _tunnel_alerts(Pipeline(dns_tunnel_candidate=True), events(_spec(name)))


def test_deployed_rule_unchanged_and_candidate_opt_in_suppresses_one_off_txt():
    legacy_txt = list(scenario('DNS_TUNNELLING'))
    assert _tunnel_alerts(Pipeline(), legacy_txt)[0][0] == 1
    benign_txt = list(events(_spec('train_txt')))
    assert _tunnel_alerts(Pipeline(), benign_txt)[0][0] == 1
    assert not _tunnel_alerts(Pipeline(dns_tunnel_candidate=True), benign_txt)
    assert Pipeline().telemetry()['dns_tunnel_candidate_enabled'] is False


def test_non_dns_and_llmnr_metadata_never_enter_candidate_history():
    event = next(events(_spec('train_long_a')))
    extractor = FeatureExtractor()
    for port in (5355, 443):
        assert extractor.update(event.model_copy(update={'dst_port': port}))['dns_query_visible'] == 0
    assert extractor.update(event.model_copy(update={'timestamp': event.timestamp + 1000}))['dns_base_queries_10s'] == 1


def test_candidate_history_is_bounded_and_never_uses_network(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'socket', lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('candidate attempted network access')))
    original = next(events(_spec('train_long_a')))
    extractor = FeatureExtractor()
    for index in range(140):
        event = original.model_copy(update={'timestamp': original.timestamp + index * 10,
                                            'dns_name': str(index) + '.' + original.dns_name})
        features = extractor.update(event)
    assert features['dns_base_queries_10s'] == 128

"""Frozen gate/integrity checks; no public captures or reserved scoring."""
import hashlib
import json
from pathlib import Path
import runpy

import pytest

from datasets.dns_tunnel_development import SCENARIOS, events
from detection.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]


def contract():
    path = ROOT / 'data/dns_tunnel_evaluation_contract.json'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == path.with_suffix('.sha256').read_text().strip()
    return json.loads(path.read_text())


def test_frozen_current_contract_matches_exact_source_and_original_protocol():
    data = contract()
    for name, digest in data['source_sha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert hashlib.sha256((ROOT / data['historical_protocol']).read_bytes()).hexdigest() == data['historical_protocol_sha256']


def test_promotion_gates_and_data_block_remain_frozen():
    data = contract()
    assert data['quality_gates'] == {
        'minimum_positive_sessions':20, 'minimum_benign_sessions':50,
        'recall_min':.8, 'precision_min':.95, 'benign_session_fpr_max':.02,
        'all_true_positives_before_completion':True,
        'early_true_positive_fraction_min':.9, 'early_query_index_max':10,
        'early_delay_ms_max':10000, 'early_conditions_combined':'AND',
        'undefined_denominator':'undefined; cannot pass', 'final_query_only_positive':'FN',
    }
    assert data['scoring_controls']['reserved_passes_max'] == 1
    assert data['scoring_controls']['reserved_set_ready'] is False
    assert data['scoring_controls']['reserved_manifest'] is None
    assert data['candidate_runtime_default_enabled'] is False
    assert Pipeline().dns_tunnel_candidate is False


def test_candidate_suppresses_synthetic_dns_posterior_without_rule_evidence():
    sequence = list(events(next(s for s in SCENARIOS if s[0] == 'val_cdn')))
    pipeline = Pipeline(dns_tunnel_candidate=True)
    pipeline.model.predict = lambda _: ('DNS_TUNNELLING', 1.0)
    assert not any(a.threat_class == 'DNS_TUNNELLING'
                   for event in sequence for a in pipeline.process(event))


def test_candidate_rule_alert_contract_survives_dns_posterior_conflict():
    sequence = list(events(next(s for s in SCENARIOS if s[0] == 'val_long_a')))
    pipeline = Pipeline(dns_tunnel_candidate=True)
    pipeline.model.predict = lambda _: ('DNS_TUNNELLING', 1.0)
    observed = [(i,a) for i,event in enumerate(sequence,1) for a in pipeline.process(event)
                if a.threat_class == 'DNS_TUNNELLING']
    i, alert = observed[0]
    assert i == 5 < len(sequence)
    assert alert.timestamp - sequence[0].timestamp == 7200
    assert alert.detection_source == 'RULE'
    assert alert.confidence_score == .8
    assert alert.severity == 'MEDIUM'
    assert alert.raw_evidence_metrics['confidence_kind'] == 'heuristic strength'
    assert alert.raw_evidence_metrics['dns_candidate_pattern'] == 'repeated_long_encoded_label'


def test_dns_persistence_failure_keeps_query_five_retryable():
    sequence = list(events(next(s for s in SCENARIOS if s[0] == 'val_long_a')))
    pipeline = Pipeline(dns_tunnel_candidate=True)
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    for event in sequence[:4]:
        assert not pipeline.process(event)

    def reject(_alerts):
        raise RuntimeError('controlled DNS persistence failure')

    with pytest.raises(RuntimeError, match='controlled DNS persistence failure'):
        pipeline.process(sequence[4], persist=reject)
    assert pipeline.processed == 4
    assert len(pipeline.extractor.sources[str(sequence[0].src_ip)]) == 4
    retried = [a for a in pipeline.process(sequence[4]) if a.threat_class == 'DNS_TUNNELLING']
    assert len(retried) == 1
    assert retried[0].raw_evidence_metrics['dns_base_queries_10s'] == 5
    assert pipeline.processed == 5


def test_diagnostic_refuses_to_overwrite_frozen_results(tmp_path, monkeypatch):
    script = ROOT / 'docs/verification/dns-contract-reconciliation-20261015/compare_versions.py'
    main = runpy.run_path(str(script))['main']
    monkeypatch.setitem(main.__globals__, 'HERE', tmp_path)
    report = tmp_path / 'comparison.json'
    report.write_text('existing immutable report')
    with pytest.raises(FileExistsError, match='Preserve frozen'):
        main()
    assert report.read_text() == 'existing immutable report'

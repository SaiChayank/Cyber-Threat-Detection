"""Offline semantic preflight regressions; frozen runtime/model bytes unchanged."""
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from datasets import audit_feature_parity as diagnostic
from datasets import check_feature_contract as check
from features.extractor import FEATURES, FeatureExtractor
from ml.model import ARTIFACT


@pytest.fixture
def pinned_history(monkeypatch):
    fixture = json.loads((Path(__file__).parent/'fixtures/feature_parity_history.json').read_text())
    assert fixture['commit'] == check.BASELINE
    assert fixture['model_sha256'] == hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()

    def blob(name):
        if name == 'ml/artifact.json':
            return ARTIFACT.read_bytes()
        item = fixture['sources'][name]
        raw = item['source'].encode()
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        return raw
    monkeypatch.setattr(check, 'blob', blob)
    monkeypatch.setattr(diagnostic, 'blob', blob)


def test_frozen_current_contract_passes_without_blessing_historical_drift(pinned_history, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Offline preflight must not train or predict')
    monkeypatch.setattr('ml.train.fit', forbidden)
    monkeypatch.setattr('ml.model.Model.predict', forbidden)
    report = check.preflight()
    assert report['current_conformance'] == 'PASS'
    assert report['historical_compatibility'] == 'FAIL'
    assert report['issues'] == [] and check.exit_code(report) == 1
    assert report['incompatible_features'] == ['byte_rate', 'byte_ratio', 'packet_rate', 'source_entropy']
    assert report['probes']['reverse_unavailable']['changes'] == {}
    assert report['extra_probes']['reverse']['zero']['observed_byte_ratio'] is None
    assert report['extra_probes']['peer']['size_cv'] == pytest.approx(1/3)
    assert report['data_policy'] == dict(controlled_metadata_only=True, training_data_used=False,
                                        validation_data_used=False, reserved_data_used=False,
                                        fit_called=False, predictions_called=False, runtime_changed=False)


@pytest.mark.parametrize('mutation,expected_path', [
    ('rate', 'probes.bucket_boundary.changes.packet_rate.after'),
    ('weighting', 'probes.packet_vs_summary.summaries.source_entropy'),
    ('reverse', 'extra_probes.reverse.zero.byte_ratio'),
])
def test_same_feature_names_cannot_hide_semantic_regressions(pinned_history, monkeypatch, mutation, expected_path):
    class MutatedExtractor(FeatureExtractor):
        def __init__(self):
            super().__init__()
            if mutation == 'weighting':
                self.global_rates.source_weight_packets = True

        def update(self, event):
            result = super().update(event)
            if result is not None:
                if mutation == 'rate':
                    result['packet_rate'] /= 2
                if mutation == 'reverse' and event.reverse_observed and event.reverse_bytes == 0:
                    result['byte_ratio'] = event.bytes
            return result

    # Monkeypatching simulates an unversioned implementation change without
    # editing source files or the feature order; behavioral probes must catch it.
    monkeypatch.setattr(diagnostic, 'FeatureExtractor', MutatedExtractor)
    monkeypatch.setattr(check, 'FeatureExtractor', MutatedExtractor)
    assert diagnostic.FEATURES == check.FEATURES == FEATURES
    report = check.preflight()
    assert report['current_conformance'] == 'FAIL'
    assert report['historical_compatibility'] == 'UNVERIFIED'
    assert expected_path in report['issues']
    assert check.exit_code(report) == 2


@pytest.mark.parametrize('left,right', [
    (None, 0), (False, 0), (True, 1), (0.0, float('nan')),
    (float('inf'), float('inf')), ({'a': 1}, {}), ({}, {'a': 1}), ([1], [1, 2]),
])
def test_shape_null_bool_and_nonfinite_values_never_silently_match(left, right):
    assert check.differences(left, right, 'probe')
    assert check.differences(0.0, 1e-12, 'probe') == []
    assert check.differences(1, 1.0, 'probe') == []


def test_manifest_checksum_and_crlf_policy(tmp_path):
    raw = check.CONTRACT.read_bytes().replace(b'\r\n', b'\n')
    path = tmp_path/'contract.json'
    path.write_bytes(raw.replace(b'\n', b'\r\n'))
    path.with_suffix('.sha256').write_text(check.CONTRACT.with_suffix('.sha256').read_text())
    assert check.load_contract(path)['contract_version'] == 'univect-gnb-semantics-20261007-v1'
    path.write_bytes(raw + b' ')
    with pytest.raises(ValueError, match='checksum mismatch'):
        check.load_contract(path)


def test_unpinned_source_fails_before_historical_execution(pinned_history, monkeypatch):
    original = check.text_hash
    monkeypatch.setattr(check, 'text_hash', lambda path: 'unexpected' if path.name == 'extractor.py' else original(path))
    def forbidden():
        pytest.fail('Unpinned source must not be executed')
    monkeypatch.setattr(check, 'historical_definitions', forbidden)
    report = check.preflight()
    assert 'current_source_sha256.features/extractor.py' in report['issues']
    assert report['historical_compatibility'] == 'UNVERIFIED' and check.exit_code(report) == 2


def test_feature_order_change_fails_even_with_same_names(pinned_history, monkeypatch):
    monkeypatch.setattr(check, 'FEATURES', list(reversed(FEATURES)))
    report = check.preflight()
    assert any(item.startswith('feature_order[') for item in report['issues'])
    assert check.exit_code(report) == 2


def test_changed_model_is_not_blessed_by_its_new_sidecar(pinned_history, tmp_path, monkeypatch):
    raw = ARTIFACT.read_bytes() + b'\n'
    path = tmp_path/'artifact.json'
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(check, 'ARTIFACT', path)
    report = check.preflight()
    assert 'model_sha256' in report['issues']
    assert report['historical_compatibility'] == 'UNVERIFIED'
    assert check.exit_code(report) == 2


def test_transform_change_fails_with_unchanged_feature_order(pinned_history, monkeypatch):
    monkeypatch.setattr(check, 'vector', lambda _: [0.0] * len(FEATURES))
    report = check.preflight()
    assert any(item.startswith('transform[') for item in report['issues'])
    assert check.exit_code(report) == 2


def test_missing_history_is_reported_as_unverified_not_compatible(monkeypatch, capsys):
    def missing(_):
        raise subprocess.CalledProcessError(128, ['git', 'show'])
    monkeypatch.setattr(check, 'blob', missing)
    assert check.main([]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report['current_conformance'] == 'ERROR'
    assert report['historical_compatibility'] == 'UNVERIFIED'


def test_cli_retains_failed_compatibility_and_never_overwrites_report(tmp_path, monkeypatch, capsys):
    report = dict(current_conformance='PASS', historical_compatibility='FAIL', issues=[])
    monkeypatch.setattr(check, 'preflight', lambda: report)
    path = tmp_path/'report.json'
    assert check.main(['--output', str(path)]) == 1
    assert json.loads(path.read_text()) == report
    capsys.readouterr()
    with pytest.raises(FileExistsError):
        check.main(['--output', str(path)])
    assert json.loads(path.read_text()) == report


def test_exit_zero_requires_both_conformance_and_compatibility():
    assert check.exit_code(dict(current_conformance='PASS', historical_compatibility='PASS')) == 0
    assert check.exit_code(dict(current_conformance='FAIL', historical_compatibility='PASS')) == 2

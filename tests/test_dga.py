"""DGA runtime contract, split isolation and passive streaming regressions."""
import hashlib
import json
import math
from pathlib import Path

import pytest

from datasets.train_dga_v2 import family_split, benign_split, evaluate, passes
from ml.dga import ARTIFACT, DgaModel, FEATURE_VERSION, NUMERIC_FEATURES, domain_label, lexical_features


def artifact(tmp_path, enabled=True):
    path = tmp_path / 'dga.json'
    numeric = {name: [0.0, 0.0, 1.0] for name in NUMERIC_FEATURES}
    numeric['log_length'][0] = 1.0
    data = dict(feature_version=FEATURE_VERSION, runtime_enabled=enabled,
                decision_threshold=.8, intercept=-2.0, weights={}, numeric_weights=numeric,
                boosted_intercept=-2.0, learning_rate=1.0,
                trees=[[[1, 2, 0, 0.0, 0.0], [-1, -1, -2, -2.0, 0.0], [-1, -1, -2, -2.0, 4.0]]])
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    return path


def test_dns_normalization_and_no_suffix_features():
    assert domain_label('WWW.Example.COM.') == 'www'
    assert domain_label('www.different.co.uk') == 'www'
    assert lexical_features('a1b2')['digit_ratio'] == .5


@pytest.mark.parametrize('name', [None, '', 'localhost', '.example.org',
                                  '_sip.example.org', 'a..org', 'a/b.org',
                                  '-name.example.org', 'name-.org',
                                  'éxample.org', 'a' * 64 + '.org'])
def test_unsupported_names_abstain(tmp_path, name):
    assert DgaModel(artifact(tmp_path)).predict(name) is None


def test_portable_scores_are_bounded_and_canonical(tmp_path):
    model = DgaModel(artifact(tmp_path))
    expected = 1 / (1 + math.exp(-2))
    assert model.predict('abcdefgh.org') == pytest.approx(expected)
    assert model.predict('ABCDEFGH.EXAMPLE.COM.') == pytest.approx(expected)
    assert 0 <= model.predict('a.org') <= 1
    assert model._score.cache_info().currsize == 2


def test_disabled_missing_and_modified_models(tmp_path):
    assert not DgaModel(tmp_path / 'missing.json').enabled
    path = artifact(tmp_path, enabled=False)
    assert DgaModel(path).predict('abcdefgh.org') is None
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='integrity'):
        DgaModel(path)


def test_related_variants_cannot_cross_family_splits():
    for variants in [('gozi_gpl', 'gozi_nasa'), ('fobber_v1', 'fobber_v2'),
                     ('murofet_v1', 'murofet_v3'), ('suppobox_1', 'suppobox_3')]:
        assert len({family_split(f) for f in variants}) == 1
    for previously_inspected in ['banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit']:
        assert family_split(previously_inspected) == 'train'
    assert benign_split('google', {'google'}) == 'train'


def test_quality_gate_rejects_recall_and_false_positive_regressions():
    assert passes(dict(recall=.8, precision=.95, false_positive_rate=.02))
    assert not passes(dict(recall=.57, precision=.99, false_positive_rate=.01))
    assert not passes(dict(recall=.9, precision=.99, false_positive_rate=.03))
    assert not passes(dict(recall=None, precision=.99, false_positive_rate=.0))
    result = evaluate([('example', 0, 'legit'), ('qzxjmv', 1, 'new-family')], [.1, .9], .8)
    assert result['tp'] == result['tn'] == 1 and result['fp'] == result['fn'] == 0


def test_unknown_ngram_counts_do_not_crash(tmp_path):
    model = DgaModel(artifact(tmp_path))
    assert math.isfinite(model.predict('zzzzzzzzzzzz.org'))


def test_lexical_score_cache_is_bounded(tmp_path):
    model = DgaModel(artifact(tmp_path))
    for n in range(4100):
        model.predict(f'host{n}.example.org')
    assert model._score.cache_info().currsize == 4096


def test_tree_inference_cannot_follow_unbounded_cycles(tmp_path):
    path = artifact(tmp_path)
    data = json.loads(path.read_text())
    data['trees'] = [[[0, 0, 0, 0.0, 0.0]]]
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match='bounded inference depth'):
        DgaModel(path).predict('abcdefgh.org')


def test_approved_lexical_model_can_emit_short_dga_with_correct_score_kind():
    from detection.pipeline import Pipeline
    from schemas.traffic_event import TrafficEvent
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    pipeline.dga_model.enabled = True
    pipeline.dga_model.threshold = .9
    pipeline.dga_model.predict = lambda _: .95
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17, dns_name='xqjmtvkp.test')
    alerts = [a for a in pipeline.process(event) if a.threat_class == 'DGA_DOMAINS']
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detection_source == 'ML' and alert.confidence_score == .95
    assert alert.raw_evidence_metrics['confidence_kind'] == 'public-domain lexical model score; uncalibrated'
    assert alert.raw_evidence_metrics['domain_label_length'] == 8
    assert alert.raw_evidence_metrics['observed_dns_name'] == event.dns_name


def test_synthetic_prediction_and_rule_cannot_bypass_approved_model():
    from detection.pipeline import Pipeline
    from schemas.traffic_event import TrafficEvent
    pipeline = Pipeline()
    pipeline.model.predict = lambda _: ('DGA_DOMAINS', .999)
    pipeline.dga_model.enabled = True
    pipeline.dga_model.predict = lambda _: .1
    pipeline.dga_model.threshold = .9
    event = TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1',
                         dst_ip='192.0.2.53', dst_port=53, protocol=17,
                         dns_name='q7x9k2z4m6b8v1j3p5d0r2s4w6.test')
    assert not [a for a in pipeline.process(event) if a.threat_class == 'DGA_DOMAINS']


def test_portable_export_matches_independent_sklearn_reference_vectors():
    reference = json.loads((Path(__file__).parent / 'fixtures/dga_export_vectors.json').read_text())
    assert hashlib.sha256(ARTIFACT.read_bytes()).hexdigest() == reference['model_sha256']
    model = DgaModel()
    for case in reference['cases']:
        label = domain_label(case['domain'])
        assert model._uncached_score(label) == pytest.approx(case['expected_score'], rel=0, abs=1e-10)

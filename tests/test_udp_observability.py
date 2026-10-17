"""Read-only diagnostic scope and exact representation-collision checks."""
import json
from types import SimpleNamespace

import pytest

from datasets import analyze_baseline_failures as diagnostic
from datasets.validate_udp_flood import aggregate_events


def test_known_opposite_labels_differ_only_by_port_and_collide_in_all_runtime_features():
    result = diagnostic.udp_collision_detail(list(aggregate_events('flood_single_large')),
                                            list(aggregate_events('benign_video_bulk')))
    assert result == dict(metadata_identical=False, different_metadata_fields=['dst_port'],
                         differing_values={'dst_port':{'positive':['9000'],'benign':['5004']}},
                         complete_runtime_features_identical=True, model_vectors_identical=True,
                         udp_rate_rule_decisions_identical=True)


def test_identical_observations_are_not_separated_by_external_label_names():
    events = list(aggregate_events('benign_video_bulk'))
    result = diagnostic.udp_collision_detail(events, events)
    assert result['metadata_identical'] and not result['different_metadata_fields']
    assert result['complete_runtime_features_identical']


def test_metadata_difference_is_not_automatically_a_feature_collision():
    events = list(aggregate_events('benign_video_bulk'))
    changed = [event.model_copy(update={'bytes':event.bytes+4000}) for event in events]
    result = diagnostic.udp_collision_detail(events, changed)
    assert result['different_metadata_fields'] == ['bytes']
    assert not result['complete_runtime_features_identical']
    assert not result['model_vectors_identical']


def test_unaligned_event_sequences_cannot_claim_a_collision():
    with pytest.raises(ValueError, match='aligned event counts'):
        diagnostic.udp_collision_detail(list(aggregate_events('flood_single_large')), [])


def test_non_udp_or_empty_inputs_cannot_support_udp_observability_claims():
    events = list(aggregate_events('flood_single_large'))
    with pytest.raises(ValueError, match='UDP metadata only'):
        diagnostic.udp_collision_detail(events, [event.model_copy(update={'protocol':6}) for event in events])
    with pytest.raises(ValueError, match='nonempty'):
        diagnostic.udp_collision_detail([], [])


def test_scoped_udp_audit_does_not_read_or_import_other_detectors(tmp_path, monkeypatch):
    source = tmp_path/'datasets/validate_udp_flood.py'
    source.parent.mkdir()
    source.write_text('known development fixture')
    path = tmp_path/'docs/verification/release-audit/udp_flood_development.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(dict(source_sha256={
        'datasets/validate_udp_flood.py':diagnostic.hashlib.sha256(source.read_bytes()).hexdigest()},
        counts={'TP':1,'TN':1}, scenarios=[dict(scenario=name, positive=positive,
            format='aggregate',events=4,verdict='TP' if positive else 'TN')
            for name, positive in [('flood_single_large',True),('benign_video_bulk',False)]])))
    module = SimpleNamespace(CASES=(('flood_single_large',True,'aggregate'),
                                   ('benign_video_bulk',False,'aggregate')),
                             aggregate_events=aggregate_events)
    imports=[]
    def only_udp(name):
        assert name == 'datasets.validate_udp_flood'
        imports.append(name)
        return module
    monkeypatch.setattr(diagnostic,'ROOT',tmp_path)
    monkeypatch.setattr(diagnostic.importlib,'import_module',only_udp)
    # Source hash recording needs these files, not other detectors' reports.
    for name in ('detection/pipeline.py','features/extractor.py','ml/model.py',
                 'features/rate_window.py','datasets/analyze_baseline_failures.py'):
        target=tmp_path/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text('fixture source pin')
    result=diagnostic.analyze(group='UDP')
    assert imports == ['datasets.validate_udp_flood']
    assert [row['group'] for row in result['modules']] == ['UDP']
    pair=result['modules'][0]['opposite_label_overlaps'][0]['paired_observability'][0]
    assert pair['complete_runtime_features_identical']
    data=json.loads(path.read_text())
    data['scenarios'][0]['positive']=False
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='labels/format'):
        diagnostic.analyze(group='UDP')


def test_unsupported_scope_is_rejected_before_other_reports_are_opened(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('An invalid scope must be rejected before file access')
    monkeypatch.setattr(diagnostic.Path, 'read_bytes', forbidden)
    with pytest.raises(ValueError,match='scoped diagnostic'):
        diagnostic.analyze(group='NOT_A_DIAGNOSTIC_SCOPE')

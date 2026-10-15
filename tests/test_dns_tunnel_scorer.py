"""Formal scoring semantics on invented metric rows and exposed development only."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from datasets import score_dns_tunnel as scorer
from datasets.dns_tunnel_development import SCENARIOS, events


@pytest.fixture
def contract():
    return scorer.load_contract()


@pytest.mark.parametrize('positive,first,expected', [
    (True, None, 'FN'), (True, 1, 'TP'), (True, 12, 'FN'),
    (False, None, 'TN'), (False, 1, 'FP'), (False, 12, 'FP'),
])
def test_session_classification_including_final_only(positive, first, expected, contract):
    row = scorer.classify(positive, 12, first, None if first is None else 1000, contract['quality_gates'])
    assert row['outcome'] == expected
    if expected != 'TP':
        assert row['early'] is False


@pytest.mark.parametrize('index,delay,early', [(10, 10000, True), (11, 9999, False),
                                            (9, 10001, False), (10, 9999, True)])
def test_joint_timing_boundary(index, delay, early, contract):
    assert scorer.classify(True, 20, index, delay, contract['quality_gates'])['early'] is early


@pytest.mark.parametrize('positive,queries,index,delay', [
    (1, 12, 5, 1), (True, 0, None, None), (True, 12, 13, 1),
    (True, 12, True, 1), (True, 12, 5, -1), (True, 12, 5, float('nan')),
    (True, 12, 5, float('inf')), (True, 12, None, 1),
])
def test_invalid_metric_observations_are_not_silently_counted(positive, queries, index, delay, contract):
    with pytest.raises(ValueError):
        scorer.classify(positive, queries, index, delay, contract['quality_gates'])


def test_confusion_metrics_and_undefined_values(contract):
    g = contract['quality_gates']
    empty = scorer.summarize([], g)
    assert [empty[k] for k in ('precision', 'recall', 'F1', 'FPR', 'early_tp_fraction')] == [None] * 5
    assert not any(empty['numerical_checks'].values())
    rows = [scorer.classify(pos, 12, first, None if first is None else 1000, g)
            for pos, first in ((True, 5), (True, 12), (False, 5), (False, None))]
    result = scorer.summarize(rows, g)
    assert [result[k] for k in ('TP', 'TN', 'FP', 'FN')] == [1, 1, 1, 1]
    assert [result[k] for k in ('precision', 'recall', 'F1', 'FPR')] == [.5] * 4
    assert result['early_tp_fraction'] == 1


def test_ninety_percent_early_gate_exactly(contract):
    g = contract['quality_gates']
    early = scorer.classify(True, 20, 5, 1000, g)
    late = scorer.classify(True, 20, 11, 1000, g)
    assert scorer.summarize([early]*9 + [late], g)['numerical_checks']['timing'] is True
    assert scorer.summarize([early]*8 + [late]*2, g)['numerical_checks']['timing'] is False


@pytest.mark.parametrize('tp,tn,fp,fn,recall_ok,precision_ok,fpr_ok', [
    (19, 49, 1, 1, True, True, True),  # precision .95, FPR .02 exactly
    (18, 49, 1, 2, True, False, True),
    (19, 48, 1, 1, True, True, False),
    (16, 50, 0, 4, True, True, True),  # recall .80 exactly
    (15, 50, 0, 5, False, True, True),
])
def test_frozen_quality_boundaries(tp, tn, fp, fn, recall_ok, precision_ok, fpr_ok, contract):
    g = contract['quality_gates']
    rows = ([scorer.classify(True,12,5,1000,g)]*tp + [scorer.classify(False,12,None,None,g)]*tn
            + [scorer.classify(False,12,5,1000,g)]*fp + [scorer.classify(True,12,None,None,g)]*fn)
    checks = scorer.summarize(rows,g)['numerical_checks']
    assert (checks['recall'], checks['precision'], checks['fpr']) == (recall_ok, precision_ok, fpr_ok)


def session(name='val_long_a'):
    spec = next(s for s in SCENARIOS if s[0] == name)
    return ({'session_id': name, 'positive': spec[2], 'tool': 'synthetic' if spec[2] else None,
             'benign_category': None if spec[2] else spec[3], 'namespace': spec[6], 'source_ip': '192.0.2.10'},
            [e.model_dump(mode='json') for e in events(spec)])


def test_real_runtime_rule_preserves_first_alert_and_suppresses_repeated_alert_count(contract):
    spec, records = session()
    row = scorer.score_session(spec, records, contract['quality_gates'])
    assert (row['outcome'], row['first_alert_query'], row['first_alert_delay_ms']) == ('TP', 5, 7200)
    assert row['queries'] == 12 and row['query_types'] == {'1': 12}
    assert row['nonnegative_interval_groups'] == {'medium': 11}
    assert row['first_alert_evidence']['dns_base_queries_10s'] == 5
    # A second independent scorer call must reset state/dedup, not inherit it.
    assert scorer.score_session(spec, records, contract['quality_gates']) == row


def test_repeated_target_alerts_count_as_one_session(contract):
    class RepeatedAlerts:
        def __init__(self):
            self.model = SimpleNamespace()
            self.extractor = SimpleNamespace(late_events=0)

        def process(self, event):
            return [SimpleNamespace(threat_class='DNS_TUNNELLING', raw_evidence_metrics={'test':True})] * 2

    spec, records = session()
    row = scorer.score_session(spec, records, contract['quality_gates'], RepeatedAlerts)
    metrics = scorer.summarize([row], contract['quality_gates'])
    assert row['first_alert_query'] == 1 and row['first_alert_delay_ms'] == 0
    assert metrics['TP'] == 1 and metrics['FP'] == 0


def test_late_questions_disclosed_and_counted_without_sorting(contract):
    spec, records = session()
    records[1], records[2] = records[2], records[1]
    result = scorer.score_session(spec, records, contract['quality_gates'])
    assert result['queries'] == 12
    assert result['late_questions_dropped'] == 1


def test_query_outside_labelled_interval_cannot_be_scored(contract):
    spec, records = session()
    spec.update(start_ms=records[1]['timestamp'], end_ms=records[-1]['timestamp'])
    with pytest.raises(scorer.EvaluationBlocked, match='labelled interval'):
        scorer.score_session(spec, records, contract['quality_gates'])


@pytest.mark.parametrize('change', ['missing_type', 'wrong_source', 'llmnr', 'namespace', 'summary'])
def test_query_truth_cannot_be_supplied_by_defaults_or_wrong_session(change, contract):
    spec, records = session()
    if change == 'missing_type': records[0].pop('dns_type')
    elif change == 'wrong_source': records[0]['src_ip'] = '192.0.2.11'
    elif change == 'llmnr': records[0]['dst_port'] = 5355
    elif change == 'namespace': records[0]['dns_name'] = 'somewhere.else.test'
    else: records[0]['packets'] = 2
    with pytest.raises(scorer.EvaluationBlocked):
        scorer.score_session(spec, records, contract['quality_gates'])


def manifest(contract):
    categories = contract['coverage']['benign_categories']
    return {'role':'reserved', 'contract_sha256':scorer.CONTRACT_SHA256,
            'scorer_sha256':scorer.sha256(scorer.Path(scorer.__file__)),
            **dict.fromkeys(scorer.PREREQUISITES, True), 'qualification_reports':{'report.json':'a'*64},
            'sessions':[{'session_id':str(i), 'independence_id':str(i), 'run_id':str(i),
                         'fragment_group':str(i), 'source_ip':'192.0.2.10', 'namespace':'example.test',
                         'label_reference':f'qualification-session-{i}', 'start_ms':0, 'end_ms':20000,
                         'events_file':f'{i}.jsonl', 'events_sha256':hashlib.sha256(str(i).encode()).hexdigest(),
                         'positive':i < 20, 'tool':'iodine' if i < 20 else None,
                         'benign_category':None if i < 20 else categories[i % 5]} for i in range(70)]}


def test_manifest_minimum_counts_and_explicit_qualification(contract):
    assert len(scorer.validate_manifest(manifest(contract), contract)) == 70


@pytest.mark.parametrize('failure', ['counts', 'positive_counts', 'category', 'tool', 'permission', 'label',
                                   'identity', 'session', 'duplicate_bytes', 'fragment', 'reports', 'contract', 'scorer'])
def test_invalid_or_duplicate_source_manifest_blocks_before_scoring(failure, contract):
    data = manifest(contract)
    if failure == 'counts': data['sessions'].pop()
    elif failure == 'positive_counts': data['sessions'].pop(0)
    elif failure == 'category':
        for row in data['sessions'][20:]: row['benign_category'] = 'cdn_cloud'
    elif failure == 'tool':
        for row in data['sessions'][:20]: row['tool'] = 'unverified'
    elif failure == 'permission': data['permission_verified'] = False
    elif failure == 'label': data['sessions'][0]['positive'] = 'malicious'
    elif failure == 'reports': data['qualification_reports'] = []
    elif failure == 'contract': data['contract_sha256'] = 'changed'
    elif failure == 'scorer': data['scorer_sha256'] = 'changed'
    else:
        key = {'identity':'independence_id', 'session':'session_id', 'duplicate_bytes':'events_sha256',
               'fragment':'fragment_group'}[failure]
        data['sessions'][1][key] = data['sessions'][0][key]
    with pytest.raises(scorer.EvaluationBlocked):
        scorer.validate_manifest(data, contract)


@pytest.mark.parametrize('start,end', [(None,10),(10,0),(True,10),(0,float('inf'))])
def test_manifest_requires_valid_explicit_label_time_bounds(start,end,contract):
    data=manifest(contract)
    data['sessions'][0].update(start_ms=start,end_ms=end)
    with pytest.raises(scorer.EvaluationBlocked,match='interval'):
        scorer.validate_manifest(data,contract)


def test_single_pass_receipt_cannot_be_reclaimed(tmp_path):
    receipt = tmp_path / 'receipt.json'
    scorer.claim_once(receipt, 'a'*64)
    first = receipt.read_bytes()
    with pytest.raises(FileExistsError):
        scorer.claim_once(receipt, 'b'*64)
    assert receipt.read_bytes() == first


def test_reserved_mode_blocks_before_manifest_or_query_access(tmp_path, monkeypatch, contract):
    monkeypatch.setattr(scorer, 'load_contract', lambda root: contract)
    def forbid(*args):
        raise AssertionError('Blocked mode must not open manifest/input')
    monkeypatch.setattr(scorer, '_local_file', forbid)
    with pytest.raises(scorer.EvaluationBlocked, match='qualified frozen data'):
        scorer.run_reserved(tmp_path / 'report.json', root=tmp_path)
    assert not list(tmp_path.iterdir())


def test_existing_development_output_preserved_before_scenario_iteration(tmp_path, monkeypatch, contract):
    monkeypatch.setattr(scorer, 'load_contract', lambda: contract)
    output = tmp_path / 'result.json'
    output.write_text('existing')
    with pytest.raises(FileExistsError):
        scorer.run_development(output)
    assert output.read_text() == 'existing'


def test_changed_contract_or_source_refused(tmp_path, contract):
    path = tmp_path / scorer.CONTRACT
    path.parent.mkdir()
    path.write_text(json.dumps(contract))
    path.with_suffix('.sha256').write_text(scorer.CONTRACT_SHA256)
    with pytest.raises(scorer.EvaluationBlocked, match='contract identity'):
        scorer.load_contract(tmp_path)


def test_changed_source_with_original_contract_refused(tmp_path, contract):
    original = scorer.ROOT / scorer.CONTRACT
    target = tmp_path / scorer.CONTRACT
    target.parent.mkdir()
    target.write_bytes(original.read_bytes())
    target.with_suffix('.sha256').write_text(scorer.CONTRACT_SHA256)
    for name in contract['source_sha256']:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes((scorer.ROOT / name).read_bytes())
    (tmp_path / 'detection/pipeline.py').write_text('changed source')
    with pytest.raises(scorer.EvaluationBlocked, match='source identity'):
        scorer.load_contract(tmp_path)


@pytest.mark.parametrize('stage', ['hash', 'validation', 'runtime'])
def test_failed_reserved_run_records_failure_and_receipt_blocks_retry(tmp_path, monkeypatch, contract, stage):
    # Artificial qualification objects and known synthetic events, never real
    # reserved data. This tests the guard lifecycle, not detector performance.
    contract['scoring_controls'].update(reserved_set_ready=True, reserved_manifest='data/manifest.json')
    monkeypatch.setattr(scorer, 'load_contract', lambda root: contract)
    (tmp_path / 'data').mkdir()
    source = tmp_path / 'known.jsonl'
    source.write_text('{}\n')
    data = manifest(contract)
    for spec in data['sessions']:
        spec['events_file'] = 'known.jsonl'
    if stage != 'hash':
        data['sessions'][0]['events_sha256'] = scorer.sha256(source)
    if stage == 'runtime':
        def fail(*_args):
            raise RuntimeError('controlled scorer runtime failure')
        monkeypatch.setattr(scorer, 'score_session', fail)
    report = tmp_path / 'qualification.json'
    report.write_text('artificial fixture qualification only')
    data['qualification_reports'] = {'qualification.json':scorer.sha256(report)}
    path = tmp_path / 'data/manifest.json'
    path.write_text(json.dumps(data))
    path.with_suffix('.sha256').write_text(scorer.sha256(path))
    output = tmp_path / 'result.json'
    error, message = ((RuntimeError, 'controlled scorer runtime failure') if stage == 'runtime' else
                      (scorer.EvaluationBlocked, 'Missing observed DNS') if stage == 'validation' else
                      (scorer.EvaluationBlocked, 'Session artifact hash mismatch'))
    with pytest.raises(error, match=message):
        scorer.run_reserved(output, tmp_path)
    assert (tmp_path / scorer.RECEIPT).is_file()
    result = json.loads(output.read_text())
    assert result['promotion_decision'] == 'NO_PROMOTION' and result['reserved_pass_consumed']
    with pytest.raises(FileExistsError):
        scorer.run_reserved(tmp_path / 'another-output.json', tmp_path)
    assert not (tmp_path / 'another-output.json').exists()


def test_artifact_paths_cannot_escape_repository(tmp_path):
    with pytest.raises(scorer.EvaluationBlocked):
        scorer._local_file(tmp_path, '../outside.jsonl')

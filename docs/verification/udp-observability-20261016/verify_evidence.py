"""Verify this scoped diagnostic and preservation; never score new data."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    result = json.loads((HERE/'report-final.json').read_text())
    assert [row['group'] for row in result['modules']] == ['UDP']
    udp = result['modules'][0]
    assert udp['saved_counts'] == {'TP':4,'TN':2,'FP':4,'FN':0}
    assert result['first_false_positive_sources'] == {'HYBRID':4}
    assert len(udp['failures']) == 4
    assert not any(result['policy'].values())
    baseline_path = ROOT/'docs/verification/baseline-failure-analysis-20261007/report.json'
    baseline = json.loads(baseline_path.read_text())
    assert result['model_sha256'] == baseline['model_sha256']
    previous = next(row for row in baseline['modules'] if row['group']=='UDP')
    assert udp['failures'] == previous['failures']
    collision = udp['opposite_label_overlaps'][0]
    assert collision['model_feature_sequence_sha256'] == previous['opposite_label_overlaps'][0]['model_feature_sequence_sha256']
    pair = collision['paired_observability'][0]
    assert pair['different_metadata_fields'] == ['dst_port']
    assert pair['complete_runtime_features_identical'] and pair['model_vectors_identical']
    assert pair['udp_rate_rule_decisions_identical'] and not pair['metadata_identical']
    for name, pin in result['current_source_sha256'].items():
        assert digest((ROOT/name).read_bytes().replace(b'\r\n',b'\n')) == pin, name
    names = subprocess.check_output(['git','ls-files'],cwd=ROOT,text=True).splitlines()
    preserved = [name for name in names if name.split('/')[0] in {
        'alerts','backend','detection','features','ingest','ml','persistence','replay','schemas','streaming'}]
    preserved += ['datasets/validate_udp_flood.py','docs/UDP_FLOOD_VALIDATION.md',
                  'docs/BASELINE_FAILURE_ANALYSIS.md',udp['report'],
                  str(baseline_path.relative_to(ROOT)).replace('\\','/'),
                  'data/dns_tunnel_evaluation_contract.json', 'data/dga_evaluation_protocol.json']
    pins = {}
    for name in preserved:
        raw = (ROOT/name).read_bytes()
        assert raw == subprocess.check_output(['git','show','8950e0b:'+name],cwd=ROOT),name
        pins[name] = digest(raw)
    assert not (ROOT/'data/dns_tunnel_reserved_pass.json').exists()
    integrity = dict(scope='T20 UDP diagnosis only', baseline_commit='8950e0b',
                     decision_DoD='PASS', detector_quality='UNRESOLVED',
                     targeted_tests_passed=23, new_diagnostic_cases=7,
                     historical_counts_unchanged=udp['saved_counts'],
                     recorded_first_false_positives_reproduced=4,
                     runtime_model_and_historical_files_unchanged=pins,
                     reserved_pass_consumed=False, runtime_changes=False,
                     training_or_candidate_activation=False,
                     new_quality_metrics=False)
    (HERE/'integrity.json').write_text(json.dumps(integrity,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:value for key,value in integrity.items()
                      if key!='runtime_model_and_historical_files_unchanged'},indent=2))


if __name__=='__main__':
    main()

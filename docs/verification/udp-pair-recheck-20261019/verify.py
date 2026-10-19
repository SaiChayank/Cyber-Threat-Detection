"""T21 prerequisite integrity only: never open packet/flow records or detectors."""
import hashlib
import json
from pathlib import Path
import sys
import importlib.util

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integrity():
    manifest=json.loads((ROOT/'data/udp_pair_qualification.json').read_text())
    protocol=ROOT/manifest['protocol']['path']
    assert sha(protocol)==manifest['protocol']['sha256']=='0c440df7b2f445045ff68331dfebc010b1363b608b3f468c650f64f9e6a50ca9'
    assert manifest['status']=='BLOCKED_NOT_QUALIFIED'
    assert manifest['selected_pair'] is None and not manifest['qualification_dod_passed']
    assert manifest['quality_gates_unchanged']==dict(recall_min=.8,precision_min=.95,
        fpr_max=.02,timing_accounting_coverage='docs/UDP_FLOOD_VALIDATION.md')
    for field in ['new_capture_records_read','new_flow_rows_read','load_overlap_measured',
                  'detector_scoring','training','reserved_evaluation','runtime_change','candidate_activation']:
        assert manifest[field] is False,field
    checked=[]
    for row in manifest['primary_lead']['readme_and_licence']:
        path=ROOT/row['local_metadata']
        if path.is_file():
            assert sha(path)==row['sha256'] and path.stat().st_size==row['bytes']
            checked.append(row['member'])
    pins=json.loads((HERE.parent/'monitor-read-recovery-20261019/integrity-after.json').read_text())
    actual={p:sha(ROOT/p) for p in pins}
    assert actual==pins
    result=dict(checks='PASS',baseline='b02a8de',qualification='BLOCKED_NOT_QUALIFIED',
        qualification_dod_passed=False,selected_pair=None,protocol_sha256=sha(protocol),
        unchanged_protected_files=len(pins),local_metadata_snapshots_verified=checked,
        packet_values_read=False,detector_experiment=False,training=False,
        reserved_evaluation=False,quality_gates_changed=False)
    (HERE/'integrity.json').write_bytes((json.dumps(result,indent=2)+'\n').encode())
    (HERE/'protected-hashes.json').write_bytes((json.dumps(actual,indent=2)+'\n').encode())
    print(json.dumps(result))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='tests':
        helper=HERE.parent/'cursor-validation-20261019/run_checks.py'
        spec=importlib.util.spec_from_file_location('udp_recheck_runner',helper)
        checks=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checks)
        checks.HERE=HERE
        checks.run('udp-tests',[sys.executable,'-B','-m','pytest',
            'tests/test_udp_flood.py','tests/test_udp_observability.py','-q','-p','no:cacheprovider'])
    else:integrity()

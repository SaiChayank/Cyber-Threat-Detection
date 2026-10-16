"""Offline qualification/preservation checks; no packet or detector imports."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    freeze = json.loads((HERE / 'protocol-freeze.json').read_text())
    manifest = json.loads((ROOT / 'data/udp_pair_qualification.json').read_text())
    receipts = json.loads((HERE / 'source-receipts.json').read_text())
    metadata = json.loads((HERE / 'archive-metadata-receipt.json').read_text())
    assert freeze['sha256'] == digest(ROOT / freeze['protocol'])
    assert manifest['protocol']['sha256'] == freeze['sha256']
    assert manifest['status'] == 'BLOCKED_NOT_QUALIFIED'
    assert manifest['selected_pair'] is None and not manifest['qualification_dod_passed']
    for key in ('new_capture_records_read', 'new_flow_rows_read', 'load_overlap_measured',
                'detector_scoring', 'training', 'reserved_evaluation', 'runtime_change',
                'candidate_activation'):
        assert manifest[key] is False, key
    assert manifest['quality_gates_unchanged'] == {
        'recall_min': .8, 'precision_min': .95, 'fpr_max': .02,
        'timing_accounting_coverage': 'docs/UDP_FLOOD_VALIDATION.md'}
    archive = receipts['orion_archive']
    assert archive['headers']['ETag'] == metadata['archive_etag']
    assert not archive['full_archive_downloaded']
    assert len(archive['members']) == 40
    assert manifest['primary_lead']['readme_and_licence'] == metadata['documents']
    snapshots = ROOT / 'data/raw/discovery/udp-pair-20261016'
    checked = 0
    for source in receipts['sources']:
        path = snapshots / (source['id'] + '.metadata')
        if path.exists():
            assert digest(path) == source['sha256'], path
            checked += 1
        if 'readme' in source and (snapshots / 'trustlab.README.md').exists():
            assert digest(snapshots / 'trustlab.README.md') == source['readme']['sha256']
            checked += 1
    for doc in metadata['documents']:
        path = ROOT / doc['local_metadata']
        if path.exists():
            assert digest(path) == doc['sha256']
            assert path.stat().st_size == doc['bytes']
            checked += 1
    # Compare canonical Git content: the Windows checkout already has mixed EOLs.
    # Also record actual local bytes; never claim they equal an LF-normalized blob.
    protected = {}
    names = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '588d2cc'],
                                    cwd=ROOT, text=True).splitlines()
    changed = subprocess.check_output(['git', 'diff', '--no-ext-diff', '--name-only',
                                       '588d2cc'], cwd=ROOT, text=True).splitlines()
    assert not (set(changed) & set(names) - {
        'docs/COMPLETION_PLAN.md', 'docs/REMAINING_WORK_PLAN.md'}), changed
    for name in names:
        # Only the two explicit current-plan pointers may alter existing files.
        if name in {'docs/COMPLETION_PLAN.md', 'docs/REMAINING_WORK_PLAN.md'}:
            continue
        path = ROOT / name
        assert path.is_file(), name
        protected[name] = digest(path)
    for response in archive['ranges'] + metadata['ranges']:
        assert 0 < response['end'] - response['start'] + 1 <= 1048576
    result = {'checks': 'PASS', 'baseline': '588d2cc', 'qualification': 'BLOCKED',
              'local_metadata_snapshots_verified': checked,
              'snapshot_check_scope': 'Only present local snapshots; none required in clean checkout',
              'protected_tracked_files_verified': len(protected),
              'preservation_semantics': 'Git canonical tracked content unchanged; SHA256 records local checkout bytes',
              'protected_sha256': protected,
              'new_packet_values_or_predictions': False,
              'scope': 'Offline metadata/manifest and tracked-file preservation; no load or accuracy test'}
    (HERE / 'integrity.json').write_text(json.dumps(result, indent=2) + '\n',
                                         encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'protected_sha256'}, indent=2))


if __name__ == '__main__':
    main()

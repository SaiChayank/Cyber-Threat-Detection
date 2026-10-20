"""Verify existing DGA evidence, without opening dataset rows or scoring a model."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def load(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def main():
    protected = load('docs/verification/monitor-replay-error-20261020/integrity-after.json')
    actual = {name: digest(ROOT / name) for name in protected}
    assert actual == protected, 'Current protected-file mismatch'
    freezes = {}
    mismatches = []
    for task in ('dga-alias-review', 'dga-positive-intake', 'dga-benign-source-review'):
        name = f'docs/verification/{task}-20261014/freeze.json'
        freeze_path = ROOT / name
        assert digest(freeze_path) == freeze_path.with_suffix('.sha256').read_text().strip()
        evidence = load(name)
        matched = 0
        for item in evidence['files']:
            current = digest(ROOT / item['path'])
            if current != item['sha256']:
                mismatches.append(dict(path=item['path'], frozen_sha256=item['sha256'], current_sha256=current))
            else:
                matched += 1
        freezes[name] = dict(sha256=digest(freeze_path), files_checked=len(evidence['files']), files_matching=matched)
    # Report the historical draft-to-sent-record mutation; never rewrite its old freeze.
    assert mismatches == [dict(path='docs/DGA_BENIGN_DATA_REQUEST.md',
        frozen_sha256='c4b8bede627ef9d7598c69eb3de782ad48a20a552603138ccedd62706bf78470',
        current_sha256='e1a96a906aeda85ef7e9a7996e3c24ad4c6f149ff20afdfa7221165eda1cb2ee')], mismatches
    protocol_path = ROOT / 'data/dga_evaluation_protocol.json'
    assert digest(protocol_path) == protocol_path.with_suffix('.sha256').read_text().strip()
    gates = load('data/dga_evaluation_protocol.json')['promotion_gates']
    assert [gates[key] for key in ('minimum_recall', 'minimum_precision',
        'maximum_domain_false_positive_rate', 'maximum_separate_benign_dns_false_positive_rate')] == [.8, .95, .02, .02]
    models = {}
    for name in ('public_dga', 'dga_v2', 'dga_weighted_candidate', 'dga_oof_candidate'):
        path = ROOT / f'ml/{name}.json'
        assert digest(path) == path.with_suffix('.sha256').read_text().strip()
        flag = 'production_enabled' if name == 'public_dga' else 'runtime_enabled'
        assert json.loads(path.read_text())[flag] is False, name
        models[str(path.relative_to(ROOT)).replace('\\', '/')] = dict(sha256=digest(path), activation_field=flag, enabled=False)
    assert not (ROOT / 'data/dga_reserved_materialization.json').exists()
    counts = load('docs/verification/dga-positive-intake-20261014/counts.json')
    assert counts['all_three_minimum_counts_passed'] is True
    assert counts['final_evaluation_ready'] is False
    assert counts['sample_selection_performed'] is False
    assert counts['training_or_scoring_performed'] is False
    result = dict(status='RECONCILED_WITH_HISTORICAL_CONTACT_DOCUMENT_MISMATCH', protected_files=len(actual),
        historical_freezes=freezes, historical_all_files_match=False,
        historical_mismatches=mismatches, model_artifacts=models,
        historical_provisional_eligible_counts={key: value['eligible_unique_first_labels']
            for key, value in counts['counts'].items()},
        counts_recomputed=False, dataset_rows_opened=False, new_evaluation_performed=False,
        scoring_or_training_performed=False, final_materialization_exists=False,
        final_dga_ready=False, blocker='Missing qualified benign strata, independent benign DNS and complete current exposure exclusions')
    (HERE / 'checks.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
    (HERE / 'integrity.json').write_bytes((json.dumps(actual, indent=2) + '\n').encode())
    print(json.dumps({key: result[key] for key in ('status', 'protected_files', 'final_dga_ready')}))


if __name__ == '__main__':
    main()

"""Integrity-only label counts for frozen candidate-positive DGA inputs.

Never import a classifier, fit a model or emit domain values. This is not the
reserved scoring pass and cannot approve the missing benign/DNS components.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

from ml.dga import domain_label


ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'docs/verification/dga-positive-intake-20261014'
GROUPS = ('bumblebee', 'qsnatch', 'sharkbot')


def collect_counts(records, exclusion_hashes):
    labels = {group: set() for group in GROUPS}
    counts = {group: Counter() for group in GROUPS}
    for name, family, actual in records:
        if family not in labels:
            continue  # Unassigned identities remain quarantined.
        counts[family]['records'] += 1
        if type(actual) is not int or actual != 1:
            counts[family]['unexpected_class_label_records'] += 1
            continue
        label = domain_label(name) if isinstance(name, str) else None
        if not label:
            counts[family]['unsupported_records'] += 1
            continue
        labels[family].add(label)
    clashes = set()
    for index, a in enumerate(GROUPS):
        for b in GROUPS[index + 1:]:
            clashes.update(labels[a] & labels[b])
    report = {}
    for group in GROUPS:
        values = labels[group]
        excluded = {value for value in values
                    if hashlib.sha256(value.encode()).hexdigest() in exclusion_hashes}
        cross = values & clashes
        eligible = values - excluded - cross
        digest = hashlib.sha256()
        for value in sorted(eligible):
            digest.update(value.encode() + b'\n')
        report[group] = dict(records=counts[group]['records'],
            unexpected_class_label_records=counts[group]['unexpected_class_label_records'],
            unsupported_records=counts[group]['unsupported_records'],
            unique_supported_before_exclusions=len(values),
            development_or_documentation_overlap_unique=len(excluded),
            cross_group_collision_unique=len(cross), eligible_unique_first_labels=len(eligible),
            eligible_label_digest=digest.hexdigest(),
            minimum_count_passed=len(eligible) >= 1000,
            label_contract_passed=not counts[group]['unexpected_class_label_records'])
    return report


def verified_json(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != path.with_suffix('.sha256').read_text().strip():
        raise ValueError('Frozen metadata integrity mismatch')
    return json.loads(raw)


def main():
    import pyarrow.parquet as pq
    from datasets.domains import domains
    from datasets.train_dga_v2 import capture_labels

    plan = verified_json(HERE / 'plan.json')
    if (plan['canonical_groups'] != list(GROUPS)
            or plan['minimum_unique_labels_per_group'] != 1000
            or plan['model_scoring_allowed'] or plan['train_or_tune_allowed']
            or plan['emit_domain_examples_allowed']):
        raise ValueError('Frozen intake boundary mismatch')
    output = HERE / 'counts.json'
    if output.exists():
        raise FileExistsError('Preserve previous integrity-only count evidence')
    source = ROOT / plan['input']
    if hashlib.sha256(source.read_bytes()).hexdigest() != plan['input_sha256']:
        raise ValueError('Input integrity mismatch')
    review = verified_json(ROOT / 'data/dga_evaluation_design_review.json')
    public = set()
    for item in review['raw_source_integrity']:
        path = ROOT / item['path']
        if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Development source integrity mismatch')
        if 'family' in item:
            public.update(label for name in domains(path) if (label := domain_label(name)))
        else:
            public.update(capture_labels(path))
    union_digest = hashlib.sha256(json.dumps(sorted(public), ensure_ascii=True,
                                separators=(',', ':')).encode()).hexdigest()
    if union_digest != plan['public_development_exclusion_digest']:
        raise ValueError('Development exclusion union mismatch')
    exclusions = {hashlib.sha256(value.encode()).hexdigest() for value in public}
    documentation = verified_json(HERE / 'documentation-exclusions.json')
    exclusions.update(documentation['union_label_sha256'])
    # Conservative exclusions from previously exposed fixtures and source literals.
    import re
    pattern = re.compile(r'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])')
    fixture_paths = list((ROOT / 'tests').rglob('*.py')) + list((ROOT / 'tests/fixtures').rglob('*.json'))
    fixture_paths += list((ROOT / 'data/lab').rglob('*.jsonl')) + list((ROOT / 'data/demo').rglob('*.jsonl'))
    fixture_paths += list((ROOT / 'replay').rglob('*.py'))
    fixture_hashes = {}
    for path in fixture_paths:
        body = path.read_bytes()
        fixture_hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(body).hexdigest()
        for name in pattern.findall(body.decode('utf-8')):
            if label := domain_label(name):
                exclusions.add(hashlib.sha256(label.encode()).hexdigest())
    def records():
        for batch in pq.ParquetFile(source).iter_batches(batch_size=65536,
                                                       columns=['domain', 'family', 'label']):
            yield from zip(*(batch.column(index).to_pylist() for index in range(3)))
    report = collect_counts(records(), exclusions)
    result = dict(scope='Positive eligibility counts only; no model scores or domain output',
        plan_sha256=(HERE / 'plan.sha256').read_text().strip(), input_sha256=plan['input_sha256'],
        counts=report, public_development_exclusion_count=len(public),
        total_exclusion_hash_count=len(exclusions), fixture_source_hashes=fixture_hashes,
        eligible_digest_format='Sorted unique first labels, UTF8 with LF after each label',
        all_three_minimum_counts_passed=all(v['minimum_count_passed'] for v in report.values()),
        all_selected_label_contracts_passed=all(v['label_contract_passed'] for v in report.values()),
        final_evaluation_ready=False, sample_selection_performed=False,
        training_or_scoring_performed=False,
        exposure_coverage_limit='Source literals do not reconstruct all dynamic historical fixtures; older cached publisher renditions not byte-certified. Complete final exposure registry still required.')
    with output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({'eligible_counts': {k: v['eligible_unique_first_labels'] for k, v in report.items()},
                      'minimum_counts_passed': result['all_three_minimum_counts_passed'],
                      'final_evaluation_ready': False}))


if __name__ == '__main__':
    main()

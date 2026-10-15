"""Metadata integrity counts must not become model acceptance evidence."""
import hashlib

from datasets.check_dga_positive_intake import collect_counts


def test_first_labels_deduplicate_across_tlds_and_subdomains():
    result = collect_counts([('same.example', 'sharkbot', 1),
                             ('same.com', 'sharkbot', 1),
                             ('same.sub.example', 'sharkbot', 1)], set())['sharkbot']
    assert result['records'] == 3
    assert result['unique_supported_before_exclusions'] == 1
    assert result['eligible_unique_first_labels'] == 1
    assert not result['minimum_count_passed']


def test_exposed_label_is_excluded_from_any_tld():
    excluded = {hashlib.sha256(b'exposed').hexdigest()}
    result = collect_counts([('exposed.example', 'bumblebee', 1)], excluded)['bumblebee']
    assert result['development_or_documentation_overlap_unique'] == 1
    assert result['eligible_unique_first_labels'] == 0


def test_cross_group_collisions_removed_from_both_families():
    report = collect_counts([('shared.example', 'bumblebee', 1),
                             ('shared.com', 'qsnatch', 1)], set())
    for group in ['bumblebee', 'qsnatch']:
        assert report[group]['cross_group_collision_unique'] == 1
        assert report[group]['eligible_unique_first_labels'] == 0


def test_unassigned_family_never_becomes_an_approved_group():
    report = collect_counts([('unassigned.example', 'different', 1)], set())
    assert all(value['records'] == 0 for value in report.values())
    assert set(report) == {'bumblebee', 'qsnatch', 'sharkbot'}


def test_unsupported_names_and_incorrect_class_labels_are_disclosed():
    report = collect_counts([('bad_name.example', 'sharkbot', 1),
                             ('label.example', 'sharkbot', 0),
                             ('truth.example', 'sharkbot', True)], set())['sharkbot']
    assert report['unsupported_records'] == 1
    assert report['unexpected_class_label_records'] == 2
    assert not report['label_contract_passed']


def test_exact_minimum_uses_unique_labels_never_row_count():
    records = [(f'label{index}.example', 'qsnatch', 1) for index in range(1000)]
    assert collect_counts(records[:999], set())['qsnatch']['minimum_count_passed'] is False
    result = collect_counts(records, set())['qsnatch']
    assert result['minimum_count_passed'] and result['eligible_unique_first_labels'] == 1000

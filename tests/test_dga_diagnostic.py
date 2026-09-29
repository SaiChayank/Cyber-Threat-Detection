"""Diagnostic-only classification, denominators and contamination checks."""
import pytest

from datasets.diagnose_dga import shape, features, guard_failures, interval, summarize, partitions, verify_metrics, dns_overlap_breakdown, overlap
from ml.dga import domain_label


@pytest.mark.parametrize('label, expected', [('12345', 'digits_only'), ('a1-b2', 'hyphenated'),
    ('a12b3c4d', 'hexadecimal_shaped'), ('g12xyz', 'mixed_alphanumeric'),
    ('example', 'letters_only_short'), ('examplelongname', 'letters_only_long')])
def test_error_shape_groups_are_exclusive(label, expected):
    assert shape(label) == expected


def test_guard_diagnosis_matches_all_existing_thresholds():
    assert guard_failures(features('google')) == ['length', 'entropy']
    assert features('google')['bigram_surprise'] == .8  # Brand name passes the English bigram cutoff.
    assert 'bigram_surprise' in guard_failures(features('there'))
    assert guard_failures(features('q7x9k2z4m6b8v1j3p5d0r2s4w6')) == []
    assert 'length' in guard_failures(features('xqjmtvkp'))


def test_bins_do_not_drop_boundary_values():
    assert interval(3.499, [3.5, 4]) == '[0, 3.5)'
    assert interval(3.5, [3.5, 4]) == '[3.5, 4)'
    assert interval(4, [3.5, 4]) == '[4, +inf)'


def test_false_positive_breakdown_uses_all_benign_rows_and_fixed_threshold():
    rows = [('example', 0, 'legit'), ('a12b3c4d', 0, 'legit'),
            ('q7x9k2z4', 1, 'family'), ('wordlike', 1, 'family')]
    result = summarize(rows, [.1, .9, .9, .2], .9)
    assert result['metrics']['tp'] == result['metrics']['fn'] == result['metrics']['fp'] == result['metrics']['tn'] == 1
    assert result['metrics']['false_positive_rate'] == .5
    assert result['patterns']['hexadecimal_shaped']['fp'] == 1
    assert result['false_negatives']['family']['missed']['count'] == 1
    assert result['error_examples']['fn'][0]['label'] == 'wordlike'
    assert sum(sum(counts.values()) for counts in result['feature_bins']['length'].values()) == 4
    with pytest.raises(ValueError, match='Every diagnostic row'):
        summarize(rows, [.1], .9)


def test_partition_audit_distinguishes_domain_overlap_from_family_overlap():
    rows = dict(train=[('train', 0, 'legit'), ('aaa', 1, 'family_v1')],
                validation=[('valid', 0, 'legit')], test=[('bbb', 1, 'family_v2')])
    captures = {'benign-benign_1': {'train'}, 'benign-benign_2': {'train', 'valid', 'bbb', 'new'}}
    result = partitions(rows, captures)
    assert result['exact_label_overlap']['train_test']['count'] == 0
    assert result['family_group_overlap']['train_test']['count'] == 1
    assert result['second_dns_overlap']['train']['count'] == 0
    assert result['second_dns_overlap']['validation']['count'] == 1
    assert result['second_dns_overlap_positive']['test']['count'] == 1


def test_saved_metrics_must_match_before_a_diagnostic_is_accepted():
    counts = dict(tp=2, fn=3, fp=4, tn=5)
    verify_metrics(counts, counts)
    with pytest.raises(ValueError, match='frozen report'):
        verify_metrics(counts, counts | {'fp': 3})


def test_dns_overlap_diagnostic_preserves_original_counts_and_denominators():
    rows = dict(validation=[('known_val', 0, 'legit')], test=[('known_test', 0, 'legit')])
    groups = dns_overlap_breakdown(rows, ['known_val', 'known_test', 'unseen'], [.95, .1, .95], .9)
    assert groups['validation_overlap']['fp'] == 1
    assert groups['comparison_overlap']['tn'] == 1
    assert groups['disjoint_from_domain_splits']['fp'] == 1
    assert sum(group['fp'] for group in groups.values()) == 2
    assert sum(group['fp'] + group['tn'] for group in groups.values()) == 3
    with pytest.raises(ValueError, match='Every DNS diagnostic label'):
        dns_overlap_breakdown(rows, ['known_val', 'unseen'], [.95], .9)


def test_fqdn_disjointness_does_not_prove_scored_label_disjointness():
    a, b = ['Google.com'], ['google.co.uk']
    assert overlap(a, b)['count'] == 0
    assert overlap(map(domain_label, a), map(domain_label, b))['count'] == 1

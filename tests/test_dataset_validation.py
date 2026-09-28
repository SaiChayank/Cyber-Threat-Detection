from collections import Counter

from datasets.validate_streaming import metrics


def test_confusion_rates_use_correct_denominators():
    result = metrics(Counter(tp=8, fn=2, fp=3, tn=7))
    assert result['recall'] == 0.8
    assert result['precision'] == 8 / 11
    assert result['false_positive_rate'] == 0.3


def test_missing_classes_are_unmeasurable_not_perfect():
    result = metrics(Counter(fn=10))
    assert result['recall'] == 0
    assert result['precision'] is None
    assert result['false_positive_rate'] is None
    assert metrics(Counter(tn=10))['recall'] is None

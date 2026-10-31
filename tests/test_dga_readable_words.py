from detection.dga_words import is_readable_label


def test_concatenated_common_words_are_readable():
    assert is_readable_label('click-now-extra-special')
    assert is_readable_label('freedownloadtools')


def test_random_strings_are_not_readable():
    assert not is_readable_label('xkqzvbnmwplt')
    assert not is_readable_label('oioberionirkutskagl')


def test_single_word_and_digits_are_not_marked_readable():
    assert not is_readable_label('google')
    assert not is_readable_label('shop1234')

"""DGA-only lexical rules; experimental rule is not active in the pipeline."""


def conservative_rule(features):
    """Existing production fallback, unchanged."""
    return (features['domain_entropy'] >= 3.5 and features['bigram_surprise'] >= .8
            and features['domain_label_length'] >= 20)


def validation_rule(features):
    """One validation-time rule hypothesis; never used for live alerts yet."""
    length = features['domain_label_length']
    vowel_ratio = features['domain_vowel_ratio']
    short = (8 <= length < 16 and features['domain_entropy'] >= 2.5
             and features['bigram_surprise'] >= .9 and vowel_ratio <= .2
             and features['domain_consonant_run'] >= .35)
    longer = (length >= 16 and features['domain_entropy'] >= 3.4
              and features['bigram_surprise'] >= .8 and vowel_ratio <= .3)
    return short or longer

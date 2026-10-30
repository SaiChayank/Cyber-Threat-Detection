"""DGA-only lexical rules; experimental rule is not active in the pipeline."""

# Two-label public suffixes (second-level registries); a pragmatic list, not the full public-suffix list.
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go'}


def registrable_name(name):
    """Name reduced to its registrable domain (label before the suffix plus the suffix).

    A generated domain's randomness is in the registrable label. Randomness in a subdomain of a
    provider's own domain (cloud load balancers, ad/CDN hashes) is infrastructure, not a DGA.
    Two-label names are returned unchanged, so ordinary DGA names are judged exactly as before.
    """
    labels = (name or '').lower().rstrip('.').split('.')
    if len(labels) <= 2:
        return '.'.join(labels)
    keep = 3 if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL and len(labels) >= 3 else 2
    return '.'.join(labels[-keep:])


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

"""Development-only DNS tunnelling rule; activation requires formal validation."""


def candidate_reason(features):
    """Return an evidence pattern for repeated, novel complete DNS questions."""
    if not features['dns_query_visible']:
        return None
    if (features['dns_base_queries_10s'] < 5
            or features['dns_base_unique_ratio_10s'] < .8
            or features['dns_base_encoded_queries_10s'] < 4):
        return None
    if (features['dns_encoded_max_label_length'] >= 40
            and features['dns_encoded_entropy'] >= 3.5):
        return 'repeated_long_encoded_label'
    if (features['dns_label_count'] >= 4
            and features['dns_encoded_max_label_length'] >= 24
            and features['dns_encoded_total_length'] >= 48
            and features['dns_encoded_entropy'] >= 3.7):
        return 'repeated_multi_label_encoding'
    return None

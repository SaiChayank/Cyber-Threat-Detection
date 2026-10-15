"""Read-only frozen plan consistency checks, never raw data or predictions.

Run from the repository root. An unavailable holdout is not a passing split.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ACQUISITION = Path('docs/verification/tls-capture-acquisition-20261013')


def digest(path, normalized=False):
    raw = Path(path).read_bytes()
    return hashlib.sha256(raw.replace(b'\r\n', b'\n') if normalized else raw).hexdigest()


def verify():
    plan = json.loads((HERE / 'plan.json').read_text(encoding='utf-8'))
    failures, checks = [], {}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            failures.append(name)

    check('plan_checksum', digest(HERE / 'plan.json', True) ==
          (HERE / 'plan.sha256').read_text().strip())
    references = plan['baseline_references']
    check('all_pinned_baseline_contents', all(digest(item['file'],
          item['checksum_policy'] == 'text_lf_normalized') == item['content_sha256']
          for item in references))
    roster_ref = plan['known_cohort_roster']
    check('known_roster_checksum', digest(roster_ref['file'], True) == roster_ref['sha256'])
    roster = json.loads(Path(roster_ref['file']).read_text(encoding='utf-8'))
    acquisition = json.loads((ACQUISITION / 'tqh-qualification-release.json').read_text())
    actual = [(s['uid'], s['intent']) for s in roster['qualified_tls_sessions']]
    expected = {(s['uid'], s['label']) for s in acquisition['qualified_sessions']}
    check('exact_qualified_roster_no_duplicate_uids', set(actual) == expected and
          len(actual) == len({uid for uid, _ in actual}) == len(expected))
    counts = dict(Counter(intent for _, intent in actual))
    check('counts_and_capture_hash_match_acquisition', counts == roster['session_counts'] ==
          acquisition['qualified_session_counts'] and
          roster['pcap_sha256'] == acquisition['pcap_sha256'] and
          roster['capture_id'] == acquisition['capture_id'])
    roles = plan['partition_roles']
    train = roles['training_development']
    check('known_role_training_development_only', roster['role'] == 'training_development'
          and roster['source_id'] in train['source_ids']
          and roster['framework_family'] in train['assigned_positive_frameworks']
          and roster['capture_id'] in train['actual_cohorts']
          and train['known_qualified_tls_sessions'] == counts and
          roster['fitting_authorized'] is False)
    check('unavailable_heldout_roles_not_fabricated', all(
          roles[role]['source_ids'] == roles[role]['provenance_groups'] ==
          roles[role]['assigned_positive_frameworks'] == roles[role]['actual_cohorts'] == []
          and roles[role]['known_qualified_tls_sessions'] is None
          and roles[role]['status'].startswith('UNAVAILABLE')
          for role in ('validation_tuning', 'reserved_evaluation')))
    policy = plan['partition_assignment_policy']
    check('no_row_split_or_related_tqh_holdout', policy['tqh_all_profiles_versions_training_development_only']
          and policy['historical_test_quarantine_preserved'] and
          all(policy[name] is False for name in ('random_row_split', 'random_uid_split',
              'component_fragmentation', 'salt_search', 'role_reassignment_after_content_or_results',
              'rebalance_by_dropping_benign')))
    frozen = json.loads(Path('ml/encrypted_session_validation.json').read_text())['frozen_gate']
    gate = plan['evaluation_protocol']['frozen_promotion_gate']
    check('original_scenario_gate_unchanged', gate == {
          'recall_min': frozen['recall_min'], 'precision_min': frozen['precision_min'],
          'benign_scenario_fpr_max': frozen['fpr_max'],
          'positive_alert_before_final_event': frozen['positive_alert_before_final_event']})
    coverage = plan['minimum_coverage_prerequisites']
    categories = {'browser_tls', 'software_update_tls', 'api_sdk_client_tls',
                  'ordinary_encrypted_application_tls'}
    check('all_benign_categories_and_independent_roles_required',
          set(coverage['benign_categories_required_in_every_role']) == categories and
          coverage['distinct_tls_c2_framework_families'] >= len(roles) and
          coverage['source_environment_provenance_groups'] >= len(roles) and
          coverage['each_source_environment_has_both_intents'] and
          coverage['benign_only_complete_capture_scenarios_required_in_every_role'])
    now = plan['readiness_now']
    fingerprint_counts = json.loads((ACQUISITION / 'acquisition-summary.json').read_text())['ja3_by_source_intent']
    check('current_fingerprint_gap_not_hidden',
          len(fingerprint_counts['malicious_c2']) == now['training_positive_ja3s'] and
          now['training_positive_ja3s'] < coverage['minimum_distinct_positive_ja3s_in_training'] and
          len(set(fingerprint_counts['malicious_c2']) & set(fingerprint_counts['benign'])) ==
          now['development_shared_positive_benign_ja3s'] == 0)
    model = json.loads(Path('ml/public_tls.json').read_text())
    check('blocked_no_training_no_reserve_access_no_promotion',
          plan['training_status'] == 'BLOCKED' and now['data_readiness_passed'] is False and
          now['reserved_identity_registered_and_sealed'] is False and
          all(plan[name] is False for name in ('training_performed', 'inference_performed',
              'promotion_performed', 'reserved_values_read')) and
          model['production_enabled'] is False and
          plan['reserved_access_policy']['read_for_tuning'] is False and
          plan['reserved_access_policy']['final_read_count'] == 1)
    return {'scope': 'Plan/checksum/known-report consistency, not final split or accuracy',
            'checks': checks, 'design_integrity_passed': not failures, 'failures': failures,
            'known_counts': counts, 'actual_validation_reserve_overlap_check':
            'NOT_ASSESSABLE: no real heldout cohorts are assigned',
            'data_readiness_passed': False, 'training_status': 'BLOCKED',
            'training_performed': False, 'new_raw_values_read': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refusing to overwrite evidence')
    report = verify()
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps({k: report[k] for k in ('design_integrity_passed', 'failures',
                     'known_counts', 'data_readiness_passed', 'training_status')}))
    raise SystemExit(0 if report['design_integrity_passed'] else 1)


if __name__ == '__main__':
    main()

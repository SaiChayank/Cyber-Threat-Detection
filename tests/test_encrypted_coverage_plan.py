"""Frozen metadata plan guards; no raw data, classifier or inference."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'docs/verification/encrypted-coverage-plan-20261014'
SPEC = importlib.util.spec_from_file_location('verify_coverage_plan', FOLDER / 'verify_plan.py')
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def copied_plan(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(VERIFIER, 'HERE', tmp_path)
    return json.loads((FOLDER / 'plan.json').read_text())


def write_copy(tmp_path, plan):
    raw = (json.dumps(plan, indent=2) + '\n').encode()
    (tmp_path / 'plan.json').write_bytes(raw)
    (tmp_path / 'plan.sha256').write_text(hashlib.sha256(raw).hexdigest())


def test_frozen_design_passes_but_empty_holdouts_never_mean_readiness(monkeypatch):
    monkeypatch.chdir(ROOT)
    result = VERIFIER.verify()
    # The 14 Oct design pinned the feature contract as frozen then. That contract was
    # deliberately re-pinned for runtime work after the 29 Oct route change, so only
    # this one baseline reference may be stale; every design check must still pass.
    plan = json.loads((FOLDER / 'plan.json').read_text(encoding='utf-8'))
    stale = [item['file'] for item in plan['baseline_references']
             if VERIFIER.digest(item['file'], item['checksum_policy'] == 'text_lf_normalized') != item['content_sha256']]
    assert stale in ([], ['data/feature_semantic_contract.json'])
    assert result['failures'] == (['all_pinned_baseline_contents'] if stale else [])
    assert not result['data_readiness_passed']
    assert result['training_status'] == 'BLOCKED'
    assert result['actual_validation_reserve_overlap_check'].startswith('NOT_ASSESSABLE')


@pytest.mark.parametrize('mutation,failed_check', [
    ('lower_gate', 'original_scenario_gate_unchanged'),
    ('enable_training', 'blocked_no_training_no_reserve_access_no_promotion'),
    ('reuse_tqh_in_validation', 'unavailable_heldout_roles_not_fabricated'),
    ('unassign_current_family', 'known_role_training_development_only'),
    ('allow_reserved_tuning', 'blocked_no_training_no_reserve_access_no_promotion'),
])
def test_invalid_role_gate_and_access_changes_fail_even_with_new_checksum(tmp_path, monkeypatch,
                                                                         mutation, failed_check):
    plan = copied_plan(tmp_path, monkeypatch)
    if mutation == 'lower_gate':
        plan['evaluation_protocol']['frozen_promotion_gate']['recall_min'] = .79
    elif mutation == 'enable_training':
        plan['training_status'] = 'READY'
    elif mutation == 'reuse_tqh_in_validation':
        plan['partition_roles']['validation_tuning']['source_ids'] = ['tqh_c2_22732327_v122']
    elif mutation == 'unassign_current_family':
        plan['partition_roles']['training_development']['assigned_positive_frameworks'] = []
    elif mutation == 'allow_reserved_tuning':
        plan['reserved_access_policy']['read_for_tuning'] = True
    write_copy(tmp_path, plan)
    result = VERIFIER.verify()
    assert result['checks']['plan_checksum']
    assert not result['design_integrity_passed']
    assert failed_check in result['failures']


def test_duplicate_session_cannot_inflate_known_training_coverage(tmp_path, monkeypatch):
    plan = copied_plan(tmp_path, monkeypatch)
    roster = json.loads((FOLDER / 'known-cohort-roster.json').read_text())
    roster['qualified_tls_sessions'].append(dict(roster['qualified_tls_sessions'][0]))
    raw = (json.dumps(roster, indent=2) + '\n').encode()
    path = tmp_path / 'roster.json'
    path.write_bytes(raw)
    plan['known_cohort_roster'].update(file=str(path), sha256=hashlib.sha256(raw).hexdigest())
    write_copy(tmp_path, plan)
    result = VERIFIER.verify()
    assert result['checks']['known_roster_checksum']
    assert not result['design_integrity_passed']
    assert 'exact_qualified_roster_no_duplicate_uids' in result['failures']

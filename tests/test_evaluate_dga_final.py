"""Mechanics of the pre-declared DGA evaluation on tiny synthetic data (no real source is scored)."""
import json
import random

import pytest

pa = pytest.importorskip('pyarrow')  # Optional research dependency; skip cleanly in a minimal install.
pq = pytest.importorskip('pyarrow.parquet')

from datasets import evaluate_dga_final as ev  # noqa: E402

CONFIG = json.loads(ev.CONFIG.read_text(encoding='utf-8'))


@pytest.mark.parametrize('family, excluded', [
    ('banjori', True), ('Zeus-NewGOZ', True), ('gameover', True), ('zloader', True), ('murofetweekly', True),
    ('suppobox_2', True), ('vawtrak_v3', True), ('qakbot', True), ('gozi_nasa', True), ('ranbyus', True),
    ('qsnatch', False), ('virut', False), ('monerominer', False), ('bazarbackdoor', False), ('conficker', False),
])
def test_development_families_and_aliases_are_excluded(family, excluded):
    assert ev.excluded_family(family, CONFIG) is excluded


def test_config_is_frozen_and_gates_match_the_protocol():
    assert CONFIG['gates'] == {'recall_min': 0.8, 'precision_min': 0.95, 'domain_fpr_max': 0.02,
                               'benign_dns_fpr_max': 0.02, 'min_benign_dns_labels': 2500, 'min_eligible_families': 10}
    assert CONFIG['candidate']['decision_threshold'] == 0.9
    assert ev.sha256(ev.ROOT / CONFIG['candidate']['artifact']) == CONFIG['candidate']['artifact_sha256']


def test_family_reservoir_caps_excludes_and_is_deterministic(tmp_path):
    rows = ([('qsnatch', f'q{i}.example.com') for i in range(500)] + [('banjori', f'b{i}.example.com') for i in range(50)]
            + [('virut', f'v{i}.example.com') for i in range(30)])
    path = tmp_path / 'dga.parquet'
    pq.write_table(pa.table({'family': [f for f, _ in rows], 'domain': [d for _, d in rows]}), path)
    config = json.loads(json.dumps(CONFIG))
    config['sampling']['per_family_cap'] = 100
    one = ev.reservoirs_by_family(path, config, random.Random(1))
    two = ev.reservoirs_by_family(path, config, random.Random(1))
    seen, kept = one
    assert one == two and 'banjori' not in kept
    assert seen == {'qsnatch': 500, 'virut': 30} and len(kept['qsnatch']) == 100 and len(kept['virut']) == 30
    assert len(set(kept['qsnatch'])) == 100 and all(d.startswith('q') for d in kept['qsnatch'])


def test_plain_reservoir_returns_requested_size(tmp_path):
    path = tmp_path / 'benign.parquet'
    pq.write_table(pa.table({'domain': [f'site{i}.com' for i in range(1000)]}), path)
    seen, sample = ev.reservoir(path, 50, random.Random(2))
    assert seen == 1000 and len(sample) == 50 and len(set(sample)) == 50


def test_dnsmasq_regex_extracts_questions_and_the_exfil_namespace_is_skipped():
    line = 'Jan 21 00:00:09 dnsmasq[3468]: query[A] www.example.org from 10.143.1.78'
    assert ev.QUERY.search(line).groups() == ('www.example.org', '10.143.1.78')
    assert ev.QUERY.search('Jan 21 dnsmasq[1]: reply www.example.org is 1.2.3.4') is None

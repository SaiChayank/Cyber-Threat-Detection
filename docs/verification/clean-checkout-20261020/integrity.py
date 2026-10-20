"""Preserve the source worktree and verify bundled artifacts in the new checkout."""
import hashlib
import json
from pathlib import Path
from rehearse import CHECKOUT, HERE, ROOT, save


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


if __name__ == '__main__':
    pins = json.loads((ROOT / 'docs/verification/monitor-replay-error-20261020/integrity-after.json').read_text())
    assert {name: digest(ROOT / name) for name in pins} == pins
    models = {}
    for name in ('artifact', 'dga_v2', 'dga_weighted_candidate', 'dga_oof_candidate',
                 'public_cic', 'public_dga', 'public_tls'):
        path = CHECKOUT / f'ml/{name}.json'
        actual = digest(path)
        assert actual == path.with_suffix('.sha256').read_text().strip()
        assert actual == digest(ROOT / f'ml/{name}.json')
        models[name] = actual
    contracts = {}
    for name in ('dga_evaluation_protocol', 'dns_tunnel_evaluation_contract'):
        path = CHECKOUT / f'data/{name}.json'
        actual = digest(path)
        assert actual == path.with_suffix('.sha256').read_text().strip()
        assert actual == digest(ROOT / f'data/{name}.json')
        contracts[name] = actual
    assert not (CHECKOUT / 'data/raw').exists()
    save('artifact-integrity.json', dict(models=models, contracts=contracts,
        source_current_protected_files_matching=len(pins), no_raw_research_data=True,
        models_retrained=False, evaluation_performed=False))
    print('PASS: seven bundled models, two frozen contracts and 130 current source pins')

"""Preserve frozen raw bytes across Git checkout line-ending policies."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from replay.demo_pack import ROOT, sha256


FROZEN_MODELS = (
    'artifact', 'dga_v2', 'dga_weighted_candidate', 'dga_oof_candidate',
    'public_cic', 'public_dga', 'public_tls',
)


def test_checkout_inventory_covers_every_checksummed_model():
    assert {p.stem for p in (ROOT / 'ml').glob('*.sha256')} == set(FROZEN_MODELS)


def test_demo_checksum_sidecars_are_newline_portable():
    manifest = json.loads((ROOT / 'data/demo/manifest.json').read_text())
    for name in ('ml/artifact.sha256', 'ml/dga_v2.sha256', 'ml/dga_weighted_candidate.sha256'):
        pin = manifest['provenance'][name]
        assert pin['newline_normalized'] is True
        assert pin['sha256'] == sha256(ROOT / name, normalize_newlines=True)


@pytest.mark.parametrize('autocrlf', ['true', 'input', 'false'])
def test_frozen_files_survive_a_windows_style_git_checkout(tmp_path, autocrlf):
    git = shutil.which('git')
    if not git:
        pytest.skip('Git is required to exercise checkout line-ending conversion')
    source = tmp_path / 'source'
    checkout = tmp_path / 'checkout'
    source.mkdir()
    names = ['.gitattributes', 'deployment/.gitkeep']
    names += [f'ml/{stem}{suffix}' for stem in FROZEN_MODELS
              for suffix in ('.json', '.sha256')]
    names += [str(path.relative_to(ROOT)).replace('\\', '/')
              for sidecar in sorted((ROOT / 'data').glob('dga_*.sha256'))
              for path in (sidecar.with_suffix('.json'), sidecar)]
    names += [str(p.relative_to(ROOT)).replace('\\', '/')
              for p in sorted((ROOT / 'data/demo').iterdir()) if p.is_file()]
    contract = json.loads((ROOT / 'data/dns_tunnel_evaluation_contract.json').read_text())
    contract_names = list(contract['source_sha256']) + [contract['historical_protocol'],
        'data/dns_tunnel_evaluation_contract.json', 'data/dns_tunnel_evaluation_contract.sha256']
    names = sorted(set(names + contract_names))
    for name in names:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    # An unprotected control proves the clone really exercises Git's conversion.
    control = b'{"control": true}\n'
    (source / 'unprotected.json').write_bytes(control)
    env = os.environ | {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}

    def run(*args, cwd=source):
        return subprocess.run([git, '-c', f'core.autocrlf={autocrlf}', *args], cwd=cwd,
                              env=env, capture_output=True, text=True, check=True)

    run('init')
    run('add', '.')
    run('-c', 'user.name=Checkout regression', '-c', 'user.email=checkout-test@localhost',
        'commit', '-m', 'Frozen packaging fixture')
    run('clone', '--no-local', '--no-hardlinks', str(source), str(checkout), cwd=tmp_path)
    assert (checkout / 'deployment/.gitkeep').is_file()
    expected_control = control.replace(b'\n', b'\r\n') if autocrlf == 'true' else control
    assert (checkout / 'unprotected.json').read_bytes() == expected_control
    # Source pins and report identities are raw-byte contracts too, not just models.
    for name in contract_names:
        assert (checkout / name).read_bytes() == (ROOT / name).read_bytes(), name
    for name, digest in contract['source_sha256'].items():
        assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == digest, name
    for name in names:
        if not name.endswith(('.json', '.jsonl')):
            continue
        raw = (checkout / name).read_bytes()
        assert raw == (ROOT / name).read_bytes(), name
        sidecar = (checkout / name).with_suffix('.sha256')
        if sidecar.is_file():
            assert hashlib.sha256(raw).hexdigest() == sidecar.read_text().strip(), name
    model_paths = [f'ml/{stem}.json' for stem in FROZEN_MODELS]
    attributes = run('check-attr', '-z', 'text', '--', *model_paths, cwd=checkout)
    values = attributes.stdout.split('\0')
    assert values[2::3] == ['unset'] * len(FROZEN_MODELS)

    from ml.model import Model
    from ml.dga import DgaModel
    Model(checkout / 'ml/artifact.json')
    for stem in ('dga_v2', 'dga_weighted_candidate', 'dga_oof_candidate'):
        assert DgaModel(checkout / f'ml/{stem}.json').enabled is False

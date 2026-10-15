"""Download pinned DGA research inputs without reading rows or running models."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/verification/dga-source-acquisition-20261014'
DEST = ROOT / 'data/raw/dga-evaluation-intake/drift-2025'
REVISION = '3b31077020cd1c013d0a75cad51042a2327c4521'
PREFIX = f'/datasets/snsec-net/dga-detection-drift26dsn/resolve/{REVISION}/raw_including_TLD/'
NAMES = {'T25_dga.parquet', 'T25_benign.parquet'}
MAX_BYTES = 400 * 1024 * 1024


def download_one(client, item, destination):
    """Exclusive bounded download; failed partial remains excluded from intake."""
    url = urlparse(item['url'])
    name = item['path'].removeprefix('raw_including_TLD/')
    if (name not in NAMES or url.scheme != 'https' or url.netloc != 'huggingface.co'
            or url.path != PREFIX + name or url.query or url.fragment):
        raise ValueError('Only pinned publisher files are allowed')
    expected = item['bytes']
    if type(expected) is not int or not 0 < expected <= MAX_BYTES:
        raise ValueError('Invalid publisher size')
    checksum = item['sha256']
    if len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum):
        raise ValueError('Invalid publisher SHA256')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / name
    partial = destination / (name + '.part')
    if path.exists() or partial.exists():
        raise FileExistsError('Preserve existing complete or partial download')
    received = 0
    digest = hashlib.sha256()
    with client.stream('GET', item['url']) as response:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError('Whole-file response required')
        with partial.open('xb') as handle:
            for chunk in response.iter_bytes(1024 * 1024):
                received += len(chunk)
                if received > expected:
                    raise ValueError('Download exceeds pinned size')
                handle.write(chunk)
                digest.update(chunk)
    if received != expected or digest.hexdigest() != checksum:
        raise ValueError('Publisher size/SHA256 mismatch; partial is excluded')
    # Publish verified bytes atomically without replacing an existing destination.
    os.link(partial, path)
    partial.unlink()
    return dict(path=path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT)
                else str(path), bytes=received, sha256=digest.hexdigest(),
                publisher_sha256_verified=True, url=item['url'])


def main():
    plan_path = EVIDENCE / 'acquisition-plan.json'
    raw = plan_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != plan_path.with_suffix('.sha256').read_text().strip():
        raise ValueError('Acquisition plan integrity mismatch')
    plan = json.loads(raw)
    if (plan['revision'] != REVISION or plan['training_allowed']
            or plan['model_scoring_allowed'] or plan['dataset_values_may_be_printed']):
        raise ValueError('Frozen acquisition boundary mismatch')
    report_path = EVIDENCE / 'download-report.json'
    if report_path.exists():
        raise FileExistsError('Preserve existing acquisition report')
    files = []
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        for item in plan['files']:
            result = download_one(client, item, DEST)
            files.append(result)
            print(f"Verified {Path(result['path']).name}: {result['bytes']} bytes", flush=True)
    report = dict(scope='Acquisition only; no rows/scoring/training',
                  plan_sha256=hashlib.sha256(raw).hexdigest(), files=files,
                  final_evaluation_ready=False)
    with report_path.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)


if __name__ == '__main__':
    main()

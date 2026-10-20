"""Exact installed requirements closure -> public PyPI advisory lookup."""
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
from urllib.request import Request, urlopen

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def save(name, value):
    path = HERE / name
    with path.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())


def request_json(url, body=None):
    encoded = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=encoded, headers={'Content-Type': 'application/json',
                                                'User-Agent': 'Univect-dependency-triage'})
    with urlopen(request, timeout=45) as response:
        data = response.read(4 * 1024 * 1024 + 1)
        if response.status != 200 or len(data) > 4 * 1024 * 1024:
            raise ValueError('Incomplete or excessive advisory response')
        return json.loads(data)


def main():
    if (HERE / 'inventory.json').exists():
        raise FileExistsError('Historical evidence exists; use a new output directory')
    roots = [Requirement(line.strip()) for line in (ROOT/'requirements.txt').read_text().splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    pending = [(requirement, 'requirements.txt') for requirement in roots]
    packages = {}
    edges = []
    while pending:
        requirement, parent = pending.pop()
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
            continue
        name = canonicalize_name(requirement.name)
        version = metadata.version(name)
        if requirement.specifier and version not in requirement.specifier:
            raise ValueError(f'Installed {name} {version} violates {requirement}')
        edges.append({'parent': parent, 'requirement': str(requirement), 'resolved': name})
        if name in packages:
            continue
        packages[name] = {'name': name, 'version': version,
                          'requires_python': metadata.metadata(name).get('Requires-Python')}
        pending.extend((Requirement(value), name) for value in metadata.requires(name) or [])
    ordered = [packages[name] for name in sorted(packages)]
    inventory = {'generated_at_utc': datetime.now(timezone.utc).isoformat(),
                 'python': platform.python_version(), 'platform': platform.platform(),
                 'requirements_sha256': hashlib.sha256((ROOT/'requirements.txt').read_bytes()).hexdigest(),
                 'roots': [str(value) for value in roots], 'packages': ordered, 'edges': edges,
                 'scope': 'Installed requirements.txt closure, including pytest and its dependencies; no optional research packages or OS scan'}
    save('inventory.json', inventory)
    query = {'queries': [{'package': {'name': p['name'], 'ecosystem': 'PyPI'},
                           'version': p['version']} for p in ordered]}
    save('osv-query.json', query)
    response = request_json('https://api.osv.dev/v1/querybatch', query)
    save('osv-response.json', response)
    results = response.get('results')
    if not isinstance(results, list) or len(results) != len(ordered):
        raise ValueError('Advisory result cardinality mismatch')
    if any(row.get('next_page_token') for row in results):
        raise ValueError('Paginated advisory response is incomplete; do not declare zero')
    ids = sorted({v['id'] for row in results for v in row.get('vulns', [])})
    for identifier in ids:
        if not all(char.isalnum() or char in '-_' for char in identifier):
            raise ValueError('Unexpected advisory identifier')
        save(identifier+'.json', request_json('https://api.osv.dev/v1/vulns/'+identifier))
    completed = subprocess.run([sys.executable,'-m','pip','check'],capture_output=True,text=True)
    save('pip-check.json', {'exit_code': completed.returncode, 'stdout': completed.stdout.strip(),
                            'stderr': completed.stderr.strip()})
    summary = {'package_count': len(ordered), 'complete_query_results': len(results),
               'advisory_ids': ids, 'pip_check_exit_code': completed.returncode,
               'status': 'NEEDS_TRIAGE' if ids else 'NO_KNOWN_ADVISORIES_IN_QUERIED_VERSIONS',
               'runtime_changed': False, 'scope': inventory['scope']}
    save('result.json', summary)
    print(json.dumps(summary,indent=2))
    if completed.returncode:
        raise SystemExit(completed.returncode)


if __name__ == '__main__':
    main()

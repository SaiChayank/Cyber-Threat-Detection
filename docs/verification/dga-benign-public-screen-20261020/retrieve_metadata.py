"""Bounded public documents only; never retrieve dataset/capture content."""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / 'data/raw/dga-benign-public-documents-20261020'
CACHE.mkdir(parents=True, exist_ok=True)
RECEIPTS = []


def fetch(name, url):
    path = CACHE / name
    assert not path.exists(), 'Preserve previous retrieval bytes'
    record = dict(name=name, requested_url=url)
    try:
        with urlopen(Request(url, headers={'User-Agent': 'Univect-public-metadata-review/1.0'}), timeout=25) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            assert len(body) <= 2 * 1024 * 1024
            record.update(status=response.status, final_url=response.url,
                content_type=response.headers.get('Content-Type'), bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest())
        path.write_bytes(body)
    except Exception as exc:
        record.update(error_type=type(exc).__name__, error=str(exc))
        body = None
    RECEIPTS.append(record)
    (HERE / 'retrievals.json').write_bytes((json.dumps(RECEIPTS, indent=2) + '\n').encode())
    return body


if __name__ == '__main__':
    for pmc in ('PMC12495040', 'PMC11033155'):
        fetch(pmc + '.xml', f'https://www.ebi.ac.uk/europepmc/webservices/rest/{pmc}/fullTextXML')
    fetch('zenodo-13330073.json', 'https://zenodo.org/api/records/13330073')
    repo = 'CborgesUFU/DNS-360-Dataset'
    repo_body = fetch('repository.json', f'https://api.github.com/repos/{repo}')
    if repo_body:
        branch = json.loads(repo_body)['default_branch']
        commit_body = fetch('commit.json', f'https://api.github.com/repos/{repo}/commits/{quote(branch)}')
        if commit_body:
            revision = json.loads(commit_body)['sha']
            tree_body = fetch('tree.json', f'https://api.github.com/repos/{repo}/git/trees/{revision}?recursive=1')
            if tree_body:
                tree = json.loads(tree_body)
                assert tree['truncated'] is False
                selected = [item for item in tree['tree'] if item['path'] in
                    ('README.md', 'License. md', 'License.md', 'data/PCAP/README.md', 'Pipe/README.md',
                     'scripts/Tranco List/README.md')]
                for index, item in enumerate(selected):
                    fetch(f'repository-document-{index}.txt',
                        f'https://raw.githubusercontent.com/{repo}/{revision}/{quote(item["path"])}')
                identity = dict(repository=repo, revision=revision, tree_truncated=False,
                    documents=selected, tree_entries=len(tree['tree']))
                (HERE / 'repository-identity.json').write_bytes((json.dumps(identity, indent=2) + '\n').encode())
    print(json.dumps([dict(name=r['name'], status=r.get('status'), bytes=r.get('bytes'), error=r.get('error_type'))
                      for r in RECEIPTS], indent=2))

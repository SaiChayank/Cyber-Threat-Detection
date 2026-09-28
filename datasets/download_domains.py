"""Official UMUDGA raw-list subset, with file and family provenance."""
import hashlib
import json
from pathlib import Path
import httpx
from datasets.download import ROOT

FAMILIES = ['legit', 'banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit']
BASE = 'https://data.mendeley.com/public-api/datasets/y8ph45msv8'


def main():
    dest = ROOT / 'data/raw/umudga'
    dest.mkdir(parents=True, exist_ok=True)
    with httpx.Client(follow_redirects=True, timeout=120, headers={'Accept': 'application/vnd.mendeley-public-dataset.1+json'}) as client:
        response = client.get(BASE + '/folders/1')
        response.raise_for_status()
        folders = response.json()
        by_id = {x['id']: x for x in folders}
        entries = []
        for family in FAMILIES:
            group = next(x for x in folders if x['name'] == family and by_id.get(x.get('parent_id'), {}).get('name') == 'Fully Qualified Domain Names')
            listing = next(x for x in folders if x['name'] == 'list' and x.get('parent_id') == group['id'])
            r = client.get(BASE + '/files', params={'folder_id': listing['id'], 'version': 1, '$start': 0, '$limit': 1000})
            r.raise_for_status()
            files = r.json()
            (dest / (family + '-files.json')).write_text(json.dumps(files, indent=2), encoding='utf-8')
            print(f'{family}: selecting a complete raw-list experiment', flush=True)
            # Select one complete generated experiment per family, rather than
            # downloading the full 30-million-domain release.
            for file in sorted(files, key=lambda x: x['filename'])[:1]:
                url = file['content_details']['download_url']
                path = dest / (family + '.txt')
                response = client.get(url, headers={'Accept': '*/*'})
                response.raise_for_status()
                if len(response.content) > 100_000_000:
                    raise ValueError('Selected domain file exceeds 100 MB')
                if len(response.content) != file['content_details']['size'] or hashlib.sha256(response.content).hexdigest() != file['content_details']['sha256_hash']:
                    raise ValueError('Publisher size/hash mismatch')
                path.write_bytes(response.content)
                entries.append(dict(family=family, file=str(path.relative_to(ROOT)), publisher_file=file, sha256=hashlib.sha256(response.content).hexdigest(), bytes=len(response.content)))
        (ROOT / 'data/umudga_manifest.json').write_text(json.dumps(dict(source='https://data.mendeley.com/datasets/y8ph45msv8/1', doi='10.17632/y8ph45msv8.1', licence='MIT', authors=['Mattia Zago', 'Manuel Gil Perez', 'Gregorio Martinez Perez'], subset='One raw-list experiment per selected family and legitimate reference', files=entries), indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()

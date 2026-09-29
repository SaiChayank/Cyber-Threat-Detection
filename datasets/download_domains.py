"""Official UMUDGA raw-list subset, with file and family provenance."""
import hashlib
import json
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import httpx
from datasets.download import ROOT

FAMILIES = ['legit', 'banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit']
BASE = 'https://data.mendeley.com/public-api/datasets/y8ph45msv8'


def expanded():
    """Bounded raw-text subset; never download or execute DGA program sources."""
    dest = ROOT / 'data/raw/umudga-expanded'
    dest.mkdir(parents=True, exist_ok=True)
    with httpx.Client(follow_redirects=True, timeout=120,
                      headers={'Accept': 'application/vnd.mendeley-public-dataset.1+json'}) as client:
        response = client.get(BASE + '/folders/1')
        response.raise_for_status()
        folders = response.json()
        parent = next(x['id'] for x in folders if x['name'] == 'Fully Qualified Domain Names')
        groups = sorted((x for x in folders if x.get('parent_id') == parent), key=lambda x: x['name'])

        def download(group):
            family = group['name']
            if not family or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_-' for c in family):
                raise ValueError('Unexpected family identifier')
            listing = next(x for x in folders if x['name'] == 'list' and x.get('parent_id') == group['id'])
            response = client.get(BASE + '/files', params={'folder_id': listing['id'], 'version': 1,
                                                          '$start': 0, '$limit': 1000})
            response.raise_for_status()
            size_tier = '100000.txt' if family == 'legit' else '10000.txt'
            file = next(x for x in response.json() if x['filename'] == size_tier)
            details = file['content_details']
            if not 0 < details['size'] <= 5_000_000:
                raise ValueError('Selected raw text file exceeds 5 MB limit')
            path = dest / (family + '.txt')
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != details['sha256_hash']:
                body = bytearray()
                with client.stream('GET', details['download_url'], headers={'Accept': '*/*'}) as stream:
                    stream.raise_for_status()
                    for chunk in stream.iter_bytes():
                        body.extend(chunk)
                        if len(body) > details['size']:
                            raise ValueError('Download exceeds declared size')
                if len(body) != details['size'] or hashlib.sha256(body).hexdigest() != details['sha256_hash']:
                    raise ValueError('Publisher size/hash mismatch')
                temporary = path.with_suffix('.part')
                temporary.write_bytes(body)
                temporary.replace(path)
            print(f'Verified {family}: {path.stat().st_size:,} bytes', flush=True)
            return dict(family=family, file=path.relative_to(ROOT).as_posix(),
                        publisher_file_id=file['id'], publisher_filename=file['filename'],
                        url=details['download_url'], sha256=details['sha256_hash'], bytes=path.stat().st_size)

        with ThreadPoolExecutor(max_workers=4) as pool:
            entries = list(pool.map(download, groups))
    manifest = dict(source='https://data.mendeley.com/datasets/y8ph45msv8/1',
                    doi='10.17632/y8ph45msv8.1', licence='MIT',
                    authors=['Mattia Zago', 'Manuel Gil Perez', 'Gregorio Martinez Perez'],
                    subset='Complete 10,000-domain raw lists per variant; 100,000-domain legitimate reference',
                    files=entries)
    (ROOT / 'data/umudga_expanded_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expanded', action='store_true', help='Download broader raw-text DGA training/evaluation subset')
    if parser.parse_args().expanded:
        return expanded()
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

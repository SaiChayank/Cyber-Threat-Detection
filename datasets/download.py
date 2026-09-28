"""Download the official TLS metadata release; never download malware programs."""
import hashlib
import json
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'data/raw/tls-18336960'


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        response = client.get('https://zenodo.org/api/records/18336960')
        response.raise_for_status()
        release = response.json()
        if release['metadata']['license']['id'] != 'cc-by-4.0':
            raise ValueError('Unexpected release licence')
        (DEST / 'release.json').write_text(json.dumps(release, indent=2), encoding='utf-8')
        manifest = []
        for entry in release['files']:
            name = entry['key']
            if name not in {'Data.md', 'Readme.md', 'winapps.parquet.zip', 'malware.parquet.zip', 'soho.parquet.zip'}:
                continue
            path = DEST / name
            checksum = entry['checksum'].split(':', 1)[1]
            if not path.exists() or hashlib.md5(path.read_bytes()).hexdigest() != checksum:
                temporary = path.with_suffix(path.suffix + '.part')
                size = 0
                digest = hashlib.md5()
                with client.stream('GET', entry['links']['self']) as stream:
                    stream.raise_for_status()
                    with temporary.open('wb') as output:
                        for chunk in stream.iter_bytes():
                            size += len(chunk)
                            if size > entry['size']:
                                raise ValueError('Download exceeded declared size')
                            digest.update(chunk)
                            output.write(chunk)
                if size != entry['size'] or digest.hexdigest() != checksum:
                    temporary.unlink(missing_ok=True)
                    raise ValueError('Publisher checksum mismatch')
                temporary.replace(path)
            item = dict(file=name, bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), publisher_checksum=entry['checksum'], url=entry['links']['self'])
            manifest.append(item)
            print(f"Verified {name}: {item['bytes']:,} bytes", flush=True)
        provenance = dict(source='https://zenodo.org/records/18336960', doi=release['doi'], author='Ondrej Rysavy', version='1.0.0', licence='CC-BY-4.0', files=manifest)
        (ROOT / 'data/public_manifest.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()

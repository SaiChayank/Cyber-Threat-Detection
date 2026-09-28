"""Registered official CIC downloads. Personal details are read from stdin only."""
import hashlib
import json
import sys
from pathlib import Path
import httpx
from datasets.download import ROOT


def main():
    # Credentials/contact data never enter committed configuration or logs.
    details = json.loads(sys.stdin.readline())
    base = 'https://cicresearch.ca/CICDataset/CIC-IDS-2017/'
    dest = ROOT / 'data/raw/cicids2017'
    dest.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        client.get(base).raise_for_status()
        r = client.post(base + 'insert.php', files={k: (None, v) for k, v in details.items()})
        r.raise_for_status()
        print('CIC registration response:', r.text[:500], flush=True)
        manifest = []
        for name in ['MachineLearningCSV.md5', 'MachineLearningCSV.zip']:
            url = base + 'download.php'
            params = {'file': 'CIC-IDS-2017/CSVs/' + name}
            path = dest / name
            temporary = path.with_suffix(path.suffix + '.part')
            offset = temporary.stat().st_size if temporary.exists() else 0
            headers = {'Range': f'bytes={offset}-'} if offset else {}
            with client.stream('GET', url, params=params, headers=headers) as stream:
                stream.raise_for_status()
                if offset and stream.status_code != 206:
                    offset = 0
                size = offset
                print(f'Downloading {name}; declared transfer bytes: {stream.headers.get("content-length", "unknown")}', flush=True)
                mark = size
                with temporary.open('ab' if offset else 'wb') as output:
                    for chunk in stream.iter_bytes():
                        size += len(chunk)
                        if size > 1_000_000_000:
                            raise ValueError('Archive exceeds 1 GB download limit')
                        output.write(chunk)
                        if size - mark >= 25_000_000:
                            print(f'{name}: {size / 1e6:.1f} MB saved', flush=True)
                            mark = size
            temporary.replace(path)
            manifest.append(dict(file=str(path.relative_to(ROOT)), bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), url=str(stream.url)))
        expected = (dest / 'MachineLearningCSV.md5').read_text().split()[0].lower()
        actual = hashlib.md5((dest / 'MachineLearningCSV.zip').read_bytes()).hexdigest()
        if expected != actual:
            raise ValueError('CIC publisher checksum mismatch')
        (ROOT / 'data/cicids2017_manifest.json').write_text(json.dumps(dict(source='https://www.unb.ca/cic/datasets/ids-2017.html', licence='Publisher permits reuse with citation', citation='Sharafaldin, Lashkari and Ghorbani (2018), Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization', files=manifest, verified_publisher_md5=actual), indent=2))
        print('CIC archive verified', flush=True)


if __name__ == '__main__':
    main()

"""Inspect registered official CIC archive listings without logging contact data."""
import json
import re
import sys
import httpx
from datasets.download import ROOT


def main():
    details = json.loads(sys.stdin.readline())
    with httpx.Client(follow_redirects=True, timeout=60) as client:
        for dataset in ['CICBellEXFDNS2021', 'CICDDoS2019']:
            base = 'https://cicresearch.ca/CICDataset/' + dataset + '/'
            client.get(base).raise_for_status()
            result = client.post(base + 'insert.php', files={k: (None, v) for k, v in details.items()})
            result.raise_for_status()
            print(dataset, result.text[:250], flush=True)
            r = client.get(base + 'browse.php')
            r.raise_for_status()
            path = ROOT / 'data/raw/discovery' / (dataset + '-listing.html')
            path.write_text(r.text, encoding='utf-8')
            print(r.text[:5000].encode('ascii', 'replace').decode(), flush=True)
            for folder in re.findall(r'href="browse.php\?p=([^"]+)"', r.text):
                child = client.get(base + 'browse.php', params={'p': folder})
                child.raise_for_status()
                (ROOT / 'data/raw/discovery' / (dataset + '-' + folder.replace('%2F', '_').replace('/', '_') + '.html')).write_text(child.text, encoding='utf-8')
                print(child.text[:8000].encode('ascii', 'replace').decode(), flush=True)


if __name__ == '__main__':
    main()

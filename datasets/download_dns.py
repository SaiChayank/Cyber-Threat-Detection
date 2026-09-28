"""Official CIC DNS-exfiltration PCAP subsets via registered download endpoint."""
import hashlib
import html
import json
import re
import sys
from urllib.parse import unquote
import httpx
from datasets.download import ROOT


def main():
    details = json.loads(sys.stdin.readline())
    base = 'https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/'
    dest = ROOT / 'data/raw/cicdns2021'
    dest.mkdir(parents=True, exist_ok=True)
    manifest = []
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        client.get(base).raise_for_status()
        reg = client.post(base + 'insert.php', files={k: (None,v) for k,v in details.items()})
        reg.raise_for_status()
        if not reg.json().get('ok'):
            raise ValueError('Registration failed')
        selected = [('benign', 'PCAP/Benign.zip')]
        for category, folder in [('light', 'PCAP/Attack_Light_Benign'), ('heavy', 'PCAP/Attack_heavy_Benign')]:
            response = client.get(base + 'browse.php', params={'p':folder})
            response.raise_for_status()
            (dest / (category + '-listing.html')).write_text(response.text, encoding='utf-8')
            candidates = re.findall(r'href="download.php\?file=([^"]+)"', response.text)
            if not candidates:
                raise ValueError(f'No capture downloads in {folder}')
            selected.append((category, unquote(html.unescape(candidates[0]))))
        print('Selected complete capture archives:', selected, flush=True)
        for category, remote in selected:
            path = dest / (category + '-' + remote.rsplit('/',1)[-1])
            temporary = path.with_suffix(path.suffix + '.part')
            size = 0
            with client.stream('GET', base + 'download.php', params={'file':remote}) as response:
                response.raise_for_status()
                with temporary.open('wb') as output:
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > 500_000_000:
                            raise ValueError('Archive exceeds 500 MB selected-file cap')
                        output.write(chunk)
            temporary.replace(path)
            manifest.append(dict(category=category, file=str(path.relative_to(ROOT)), bytes=size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), url=str(response.url), label_scope='Benign reference' if category == 'benign' else 'Capture contains attack and benign traffic; no blanket per-flow attack label'))
            print(f'Downloaded {path.name}: {size:,} bytes', flush=True)
        (ROOT / 'data/cicdns2021_manifest.json').write_text(json.dumps(dict(source='https://www.unb.ca/cic/datasets/dns-exf-2021.html', licence='CIC reuse with citation', subset='Full benign archive and one complete capture archive each for light/heavy exfiltration', files=manifest), indent=2))


if __name__ == '__main__':
    main()

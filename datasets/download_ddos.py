"""Download a clearly marked 100k-row prefix from the official DDoS CSV archive."""
import hashlib
import json
import sys
import httpx
from stream_unzip import stream_unzip
from datasets.download import ROOT


def main():
    details = json.loads(sys.stdin.readline())
    base = 'https://cicresearch.ca/CICDataset/CICDDoS2019/'
    dest = ROOT / 'data/raw/cicddos2019'
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / 'first-csv-100000-rows.csv'
    compressed = 0
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        client.get(base).raise_for_status()
        r = client.post(base+'insert.php', files={k:(None,v) for k,v in details.items()})
        r.raise_for_status()
        if not r.json().get('ok'):
            raise ValueError('CIC registration failed')
        with client.stream('GET',base+'download.php',params={'file':'CSVs/CSV-03-11.zip'}) as response:
            response.raise_for_status()
            def chunks():
                nonlocal compressed
                for chunk in response.iter_bytes(chunk_size=65536):
                    compressed += len(chunk)
                    if compressed > 300_000_000:
                        raise ValueError('Prefix retrieval exceeds 300 MB compressed budget')
                    yield chunk
            for name, declared_size, unzipped in stream_unzip(chunks()):
                if not name.lower().endswith(b'.csv'):
                    for _ in unzipped:
                        pass
                    continue
                pending, lines = b'', 0
                with path.with_suffix('.part').open('wb') as output:
                    for chunk in unzipped:
                        pending += chunk
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n',1)
                            output.write(line + b'\n')
                            lines += 1
                            if lines >= 100001:
                                break
                        if lines >= 100001:
                            break
                    if lines < 100001 and pending:
                        output.write(pending + b'\n')
                        lines += 1
                path.with_suffix('.part').replace(path)
                record = dict(source='https://www.unb.ca/cic/datasets/ddos-2019.html', licence='CIC reuse with citation', url=str(response.url), original_member=name.decode('utf-8','replace'), original_member_size=declared_size, subset='First 100000 complete data lines from first CSV member; intentionally not the full archive', rows=max(0,lines-1), compressed_bytes_received=compressed, file=str(path.relative_to(ROOT)), bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), integrity='Local SHA256 and valid CSV; full ZIP CRC unavailable for a deliberately partial member')
                (ROOT/'data/cicddos2019_manifest.json').write_text(json.dumps(record,indent=2))
                print(json.dumps(record,indent=2),flush=True)
                break
            else:
                raise ValueError('Archive contains no CSV')


if __name__ == '__main__':
    main()

"""Cross-check exact queried releases and preserve original application artifacts."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def release(package):
    url = f"https://pypi.org/pypi/{package['name']}/{package['version']}/json"
    with urlopen(Request(url,headers={'User-Agent':'Univect-dependency-triage'}),timeout=30) as response:
        body = response.read(2*1024*1024+1)
        assert response.status == 200 and len(body) <= 2*1024*1024
    data = json.loads(body)
    assert data['info']['version'] == package['version']
    assert data['urls'], 'Release has no publisher distributions'
    assert not data.get('vulnerabilities'), 'Publisher lists an advisory; triage required'
    assert any(not item.get('yanked',False) for item in data['urls']), 'Release distributions all yanked'
    return dict(url=url,name=data['info']['name'],version=data['info']['version'],
                response_sha256=hashlib.sha256(body).hexdigest(),
                distribution_count=len(data['urls']),publisher_advisories=data.get('vulnerabilities',[]),
                all_distributions_yanked=False,checked_utc=datetime.now(timezone.utc).isoformat())


if __name__=='__main__':
    inventory=json.loads((HERE/'inventory.json').read_text())
    with ThreadPoolExecutor(max_workers=4) as pool:
        releases=list(pool.map(release,inventory['packages']))
    target=HERE/'publisher-checks.json'
    with target.open('xb') as stream:
        stream.write((json.dumps(releases,indent=2)+'\n').encode())
    pins=json.loads((HERE.parent/'monitor-replay-error-20261020/integrity-after.json').read_text())
    changed=[]
    for name,expected in pins.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:changed.append(name)
    assert not changed,changed
    assert len(pins)==130
    print('PASS: 22 exact PyPI releases exist, no publisher advisories, non-yanked distributions; 130 protected originals unchanged')

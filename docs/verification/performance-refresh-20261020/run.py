"""Preserve previous reports; run declared measurements sequentially once."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('performance_checks',HERE.parent/'cursor-validation-20261019/run_checks.py')
checks=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE=HERE


if __name__=='__main__':
    originals={}
    for name in ['benchmarks/latest.json','benchmarks/delivery_latest.json']:
        source=ROOT/name
        body=source.read_bytes()
        copy=HERE/('previous-'+source.name)
        with copy.open('xb') as target:target.write(body)
        originals[name]=hashlib.sha256(body).hexdigest()
    (HERE/'previous-report-hashes.json').write_bytes((json.dumps(originals,indent=2)+'\n').encode())
    checks.run('core',[sys.executable,'-B','-m','benchmarks.run','--events','20000'])
    core=json.loads((ROOT/'benchmarks/latest.json').read_text())
    assert core['throughput_pass'] and core['latency_pass'],'Core gate failed; do not retry to cherry-pick'
    checks.run('delivery',[sys.executable,'-B','-m','benchmarks.delivery','--events','100'])
    print('SCOPED_PERFORMANCE_PASS',flush=True)

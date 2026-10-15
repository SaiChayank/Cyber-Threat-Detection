"""Compare known DNS development traces only; never read a public capture."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COMMIT = '12c7933715662e8291154304c44607b429085d11'
OLD_PIPELINE = 'c01de15ed0fff1c3576cd757e0665c78358bd3a0efd365c3ddb11e32c9efdb86'

WORKER = r'''
import json,sys
from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor
from features.dns_tunnel import FEATURE_NAMES
from schemas.traffic_event import TrafficEvent
output=[]
for spec in json.load(open(sys.argv[1])):
    pipeline=Pipeline(dns_tunnel_candidate=True)
    # Same rule-only arm as the prior development comparison, not runtime activation.
    pipeline.model.predict=lambda _:('BENIGN',1.0)
    extractor=FeatureExtractor()
    traces=[]
    for index,raw in enumerate(spec['events'],1):
        event=TrafficEvent(**raw)
        f=extractor.update(event)
        alerts=[a.to_dict() for a in pipeline.process(event) if a.threat_class=='DNS_TUNNELLING']
        # UUID/creation time and measured CPU latency are intentionally excluded.
        alerts=[{k:v for k,v in a.items() if k not in ('alert_id','created_at_ms')} for a in alerts]
        traces.append({'query':index,'features':{k:f[k] for k in FEATURE_NAMES},'alerts':alerts})
    first=next((t['query'] for t in traces if t['alerts']),None)
    output.append({'scenario':spec['scenario'],'first_alert_query':first,
                   'first_alert_delay_ms':None if first is None else spec['events'][first-1]['timestamp']-spec['events'][0]['timestamp'],
                   'traces':traces})
json.dump(output,open(sys.argv[2],'w'),indent=2)
'''


def main():
    if any((HERE / name).exists() for name in ('initial-integrity.json', 'comparison.json')):
        raise FileExistsError('Preserve frozen reconciliation evidence; use a new evidence directory')
    sys.path.insert(0, str(ROOT))
    from datasets.dns_tunnel_development import SCENARIOS, events
    protected = {}
    for directory in ('detection', 'features', 'schemas', 'ingest', 'ml', 'persistence'):
        for path in (ROOT / directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                protected[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (HERE / 'initial-integrity.json').write_text(json.dumps(protected, indent=2) + '\n')
    old = subprocess.check_output(['git', 'show', f'{COMMIT}:detection/pipeline.py'], cwd=ROOT)
    assert hashlib.sha256(old).hexdigest() == OLD_PIPELINE
    (HERE / 'historical-pipeline.py.txt').write_bytes(old)
    diff = subprocess.check_output(['git', 'diff', COMMIT, '--', 'detection/pipeline.py',
                                   'features/extractor.py', 'features/rate_window.py',
                                   'ingest/metadata.py', 'schemas/traffic_event.py'], cwd=ROOT)
    (HERE / 'source-diff.patch').write_bytes(diff)
    # Do not overwrite the original frozen development report.
    with tempfile.TemporaryDirectory(prefix='univect-dns-contract-') as directory:
        temp = Path(directory).resolve()
        historical = temp / 'historical'
        historical.mkdir()
        names = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', COMMIT,
                                         '--', 'detection', 'features', 'schemas', 'ml'],
                                        cwd=ROOT, text=True).splitlines()
        for name in names:
            destination = (historical / name).resolve()
            if not destination.is_relative_to(historical) or not name.endswith(('.py', '.json', '.sha256')):
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(subprocess.check_output(['git', 'show', f'{COMMIT}:{name}'], cwd=ROOT))
        inputs = temp / 'known-development.json'
        inputs.write_text(json.dumps([{'scenario':s[0], 'events':[e.model_dump(mode='json') for e in events(s)]}
                                     for s in SCENARIOS]))
        results = []
        for name, source in (('historical', historical), ('current', ROOT)):
            target = temp / (name + '.json')
            # -c executes only this fixed worker; each subprocess imports one source tree.
            subprocess.run([sys.executable, '-B', '-c', WORKER, str(inputs), str(target)],
                           cwd=source, check=True)
            rows = json.loads(target.read_text())
            (HERE / (name + '-development-traces.json')).write_text(json.dumps(rows, indent=2) + '\n')
            results.append(rows)
    before, after = results
    features = sum(a['features'] != b['features'] for old, new in zip(before, after)
                   for a, b in zip(old['traces'], new['traces']))
    alerts = sum(a['alerts'] != b['alerts'] for old, new in zip(before, after)
                 for a, b in zip(old['traces'], new['traces']))
    timing = sum((a['first_alert_query'], a['first_alert_delay_ms']) !=
                 (b['first_alert_query'], b['first_alert_delay_ms']) for a, b in zip(before, after))
    changed = [name for name, sha in protected.items()
               if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != sha]
    assert not changed
    summary = {'historical_commit':COMMIT,'historical_pipeline_sha256':OLD_PIPELINE,
               'scenarios':len(after),'events':sum(len(x['traces']) for x in after),
               'dns_feature_vector_disagreements':features,'dns_stable_alert_disagreements':alerts,
               'first_alert_query_or_capture_time_disagreements':timing,
               'protected_files_unchanged':len(protected),'reserved_access':False,
               'scope':'Already exposed 20 synthetic development scenarios only; no production/generalization claim',
               'first_alerts':[ {k:v for k,v in x.items() if k!='traces'} for x in after]}
    (HERE / 'comparison.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='first_alerts'}))


if __name__ == '__main__':
    main()

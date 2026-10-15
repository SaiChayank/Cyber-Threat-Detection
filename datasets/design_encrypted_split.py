"""Metadata-only sample/capture/family-safe development split; never fit models."""
import argparse
import hashlib
import json
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from datasets.audit_encrypted_data import ANNOTATIONS, ROOT, partition
from datasets.tls import label
from datasets.train_tls import group


class Components:
    def __init__(self):
        self.parent = {}

    def find(self,node):
        self.parent.setdefault(node,node)
        root = node
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[node] != node:
            parent = self.parent[node]
            self.parent[node] = root
            node = parent
        return root

    def link(self,left,right):
        a,b = self.find(left),self.find(right)
        if a != b:
            self.parent[max(a,b)] = min(a,b)


def annotations():
    import pyarrow.parquet as pq
    for collection in ('winapps','malware'):
        with zipfile.ZipFile(ROOT/f'data/raw/tls-18336960/{collection}.parquet.zip') as archive:
            for member in sorted(archive.namelist()):
                if member.endswith('.parquet'):
                    with archive.open(member) as file:
                        for batch in pq.ParquetFile(file).iter_batches(columns=ANNOTATIONS,batch_size=1024,use_threads=False):
                            for row in batch.to_pylist():
                                yield collection,member,row


def design(records):
    links = Components()
    member_counts = defaultdict(Counter)
    test_nodes = set()
    for collection,member,row in records:
        node = f'member:{collection}:{member}'
        links.find(node)
        truth = label(row,collection)
        member_counts[node][truth] += 1
        if row.get('meta.sample.id'):
            sample = hashlib.sha256(str(row['meta.sample.id']).encode()).hexdigest()
            links.link(node,f'sample:{collection}:{sample}')
        if truth != 'UNLABELLED':
            family = 'group:'+group(row,collection)
            links.link(node,family)
            if partition(row,collection)=='historical_test':
                test_nodes.add(family)
    grouped = defaultdict(list)
    for node in links.parent:
        grouped[links.find(node)].append(node)
    quarantined = {links.find(node) for node in test_nodes}
    components = []
    for root,nodes in grouped.items():
        nodes = sorted(nodes)
        signature = hashlib.sha256('\n'.join(nodes).encode()).hexdigest()
        members = [node for node in nodes if node.startswith('member:')]
        counts = Counter()
        for member in members:
            counts.update(member_counts[member])
        assigned = ('quarantine_historical_test' if root in quarantined else
                    'unlabelled' if not (counts['BENIGN_REFERENCE']+counts['MALWARE_RELATED']) else
                    'train' if int(signature[:8],16)%10 < 6 else 'validation')
        components.append(dict(component_sha256=signature,partition=assigned,label_counts=dict(counts),
                               members=members,groups=[node for node in nodes if node.startswith('group:')],
                               sample_ids_sha256=[node for node in nodes if node.startswith('sample:')]))
    components.sort(key=lambda c:c['component_sha256'])
    counts = {part:{label:sum(c['label_counts'].get(label,0) for c in components if c['partition']==part)
                    for label in ('BENIGN_REFERENCE','MALWARE_RELATED','UNLABELLED')}
              for part in ('train','validation','quarantine_historical_test','unlabelled')}
    overlaps = {}
    for key in ('members','groups','sample_ids_sha256'):
        seen = {part:{node for c in components if c['partition']==part for node in c[key]}
                for part in ('train','validation','quarantine_historical_test')}
        overlaps[key] = {f'{a}:{b}':len(seen[a]&seen[b]) for a,b in
                        (('train','validation'),('train','quarantine_historical_test'),
                         ('validation','quarantine_historical_test'))}
    gate = (all(value==0 for checks in overlaps.values() for value in checks.values()) and
            all(counts[part][truth]>0 for part in ('train','validation')
                for truth in ('BENIGN_REFERENCE','MALWARE_RELATED')))
    return dict(scope='Metadata-only development split feasibility; weak labels, completed sessions, no reserved features',
                gate_passed=gate,development_counts=counts,overlap_checks=overlaps,
                component_counts=dict(Counter(c['partition'] for c in components)),components=components,
                policy=dict(row_shuffle=False,salt_search=False,feature_reads=False,training=False,
                            inference=False,reserved_data=False,runtime_changes=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    source = json.loads((ROOT/'data/public_manifest.json').read_text())
    for file in source['files']:
        raw = (ROOT/'data/raw/tls-18336960'/file['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=file['sha256']:
            raise ValueError('Source hash mismatch')
    report = design(annotations())
    report.update(source_manifest_sha256=hashlib.sha256((ROOT/'data/public_manifest.json').read_bytes()).hexdigest(),
                  source_files=source['files'],audit_date='2026-10-12')
    raw = (json.dumps(report,indent=2)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('xb') as file:file.write(raw)
    args.output.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest()+'\n',encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('gate_passed','development_counts','component_counts','overlap_checks')},indent=2))
    raise SystemExit(0 if report['gate_passed'] else 1)


if __name__=='__main__':
    main()

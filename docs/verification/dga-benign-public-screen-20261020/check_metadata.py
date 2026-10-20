"""Check bounded source receipts and preservation; no dataset values or model calls."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / 'data/raw/dga-benign-public-documents-20261020'
sys.path.insert(0, str(ROOT))
from ml.dga import domain_label


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


if __name__ == '__main__':
    receipts = json.loads((HERE / 'retrievals.json').read_text())
    assert len(receipts) == 13
    assert all(record.get('status') == 200 for record in receipts)
    for record in receipts:
        path = CACHE / record['name']
        assert path.stat().st_size == record['bytes']
        assert digest(path) == record['sha256']
    identity = json.loads((HERE / 'repository-identity.json').read_text())
    tree = json.loads((CACHE / 'tree.json').read_text())
    assert tree['truncated'] is False
    tree_by_path = {item['path']: item for item in tree['tree']}
    documents = []
    selected = [(f'repository-document-{n}.txt', item['path']) for n, item in enumerate(identity['documents'])]
    selected += [('generation-methodology.txt', 'Pipe/Traffic Generation Methodology'),
                 ('tranco-readme.txt', 'scripts/Tranco List/Readme')]
    for local_name, source_path in selected:
        body = (CACHE / local_name).read_bytes()
        git_hash = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        assert git_hash == tree_by_path[source_path]['sha']
        documents.append(dict(path=source_path, git_blob_sha1=git_hash))
    save('document-identities.json', dict(revision=identity['revision'], documents=documents))
    # Conservative documentation exclusions only; not domain observations or truth labels.
    pattern = re.compile(r'(?<![a-zA-Z0-9_-])(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(?![a-zA-Z0-9_-])')
    labels = set()
    documentation = [CACHE / name for name, _ in selected] + [CACHE / 'PMC12495040.xml', CACHE / 'PMC11033155.xml']
    for path in documentation:
        for candidate in pattern.findall(path.read_text(encoding='utf-8')):
            label = domain_label(candidate)
            if label:
                labels.add(hashlib.sha256(label.encode()).hexdigest())
    snippet_names = ['redirector.googlevideo.com', 'ata000g10289.badsite.com', 'badsite.com',
        'google.com', 'spamdomain.example.multi.surbl.org', '4.3.2.1.multi.surbl.org',
        'dnsbl.example.net', 'ractertest.com', 'www.gen.uk', 'google.com.localdomain', 'com.google']
    labels.update(hashlib.sha256(domain_label(value).encode()).hexdigest() for value in snippet_names)
    save('documentation-exclusions.json', dict(scope='Conservative current document and explicitly recorded search-snippet first-label hashes; not a complete final registry',
        canonicalizer='ml.dga.domain_label', hash_algorithm='SHA256 UTF8 canonical first label',
        first_label_hashes=sorted(labels), count=len(labels),
        must_merge_before_materialization=True, source_role_assignment=False))
    protected = json.loads((ROOT / 'docs/verification/monitor-replay-error-20261020/integrity-after.json').read_text())
    assert {name: digest(ROOT / name) for name in protected} == protected
    assert not (ROOT / 'data/dga_reserved_materialization.json').exists()
    z1 = json.loads((CACHE / 'zenodo-13330073.json').read_text())
    z2 = json.loads((CACHE / 'zenodo-10887463.json').read_text())
    assert z1['id'] == 14332167 and z1['metadata']['license']['id'] == 'cc-by-4.0'
    assert z2['id'] == 10887463 and z2['metadata']['license']['id'] == 'cc-by-4.0'
    save('checks.json', dict(status='PASS_METADATA_IDENTITY_AND_PRESERVATION',
        retrievals_verified=len(receipts), git_document_identities_verified=len(documents),
        current_protected_files_matching=len(protected), dataset_values_opened=False,
        bulk_datasets_downloaded=0, new_evaluation_or_training=False,
        qualified_reserved_roles=0, final_dga_ready=False,
        exposure_limit='Global historical/dynamic and prior cached-search completeness remains unresolved'))
    print('PASS: 13 public document receipts, 6 Git blobs, 130 current protected files; 0 qualified reserved roles')

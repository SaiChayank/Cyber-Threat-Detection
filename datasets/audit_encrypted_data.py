"""Read-only encrypted development inventory; no model training/inference.

Historical test members are routed on annotations, never scanned for features.
SOHO remains unlabelled. Session metadata is not reconstructed as packet events.
"""
import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from datasets.tls import label
from datasets.train_tls import bucket, group
from ingest.pcap_reader import PcapReader, validate_header

ROOT = Path(__file__).resolve().parents[1]
ANNOTATIONS = ['meta.application.name','meta.malware.family','meta.system.service','meta.sample.id','meta.system.os']
HANDSHAKE = ['tls.ccs','tls.cext','tls.ja3']


def partition(row, collection):
    if label(row, collection) == 'UNLABELLED':
        return 'unlabelled'
    value = bucket(group(row, collection))
    return 'train' if value < 6 else 'validation' if value < 8 else 'historical_test'


def array_status(value):
    if value is None:
        return 'missing'
    if not isinstance(value,list) or any(not (
            type(v) is int and 0 <= v <= 65535 or
            isinstance(v,str) and re.fullmatch(r'[0-9a-fA-F]{4}',v)) for v in value):
        return 'invalid'
    return 'present_nonempty' if value else 'present_empty'


def sample_day(value):
    text = str(value or '')
    length,fmt = (8,'%Y%m%d') if text.startswith(('19','20')) else (6,'%y%m%d')
    try:
        return datetime.strptime(text[:length],fmt).date().isoformat()
    except ValueError:
        return None


def audit_archive(path, collection):
    import pyarrow.parquet as pq
    totals = Counter()
    coverage = defaultdict(Counter)
    groups = defaultdict(set)
    samples = defaultdict(set)
    days = defaultdict(set)
    schemas = set()
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith('.parquet'):
                continue
            totals['members'] += 1
            with archive.open(name) as file:
                parquet = pq.ParquetFile(file)
                totals['footer_rows'] += parquet.metadata.num_rows
                schemas.update(parquet.schema_arrow.names)
                if collection == 'soho':
                    continue  # Footer/schema only: never invent supervised truth.
                routes = set()
                for batch in parquet.iter_batches(batch_size=1024, columns=ANNOTATIONS, use_threads=False):
                    for row in batch.to_pylist():
                        part = partition(row, collection)
                        totals[f'annotation_rows:{part}'] += 1
                        routes.add(part)
                        if part != 'unlabelled' and row.get('meta.sample.id'):
                            samples[part].add(hashlib.sha256(str(row['meta.sample.id']).encode()).hexdigest())
                        if part in ('train','validation'):
                            groups[part].add(group(row,collection))
                            day = sample_day(row.get('meta.sample.id'))
                            if day:
                                days[part].add(day)
                if 'historical_test' in routes:
                    totals['members_excluded_from_feature_read'] += 1
                    continue  # Skip entire mixed members, not just final rows.
                if not routes & {'train','validation'}:
                    continue
                totals['members_feature_read'] += 1
                # Read only observable ClientHello fields, plus routing annotations.
                # No completed-flow totals, reverse measurements or record sequence.
                for batch in parquet.iter_batches(batch_size=1024, columns=ANNOTATIONS+HANDSHAKE, use_threads=False):
                    for row in batch.to_pylist():
                        part = partition(row, collection)
                        if part not in ('train','validation'):
                            continue
                        key = f'{part}:{label(row,collection)}'
                        counts = coverage[key]
                        counts['rows'] += 1
                        states = {field:array_status(row.get(field)) for field in HANDSHAKE[:2]}
                        for field,status in states.items():
                            counts[f'{field}:{status}'] += 1
                            if status=='present_nonempty':
                                counts[f'{field}:hex_encoded_rows'] += all(isinstance(v,str) for v in row[field])
                        counts['ja3_present' if row.get('tls.ja3') else 'ja3_missing'] += 1
                        counts['joint_valid_arrays'] += all(status.startswith('present_') for status in states.values())
                        counts['joint_nonempty_arrays'] += all(status=='present_nonempty' for status in states.values())
    return dict(collection=collection, totals=dict(totals), schema_fields=sorted(schemas),
                development_coverage={key:dict(value) for key,value in coverage.items()},
                groups={key:dict(count=len(value), names=sorted(value)) for key,value in groups.items()},
                sample_dates={key:sorted(value) for key,value in days.items()},
                train_validation_group_overlap=sorted(groups['train'] & groups['validation']),
                sample_counts={key:len(value) for key,value in samples.items()},
                sample_overlap_counts={f'{a}:{b}':len(samples[a] & samples[b])
                                       for a,b in (('train','validation'),('train','historical_test'),
                                                   ('validation','historical_test'))},
                train_validation_date_overlap=sorted(days['train'] & days['validation']),
                label_scope='Unlabelled, footer only' if collection=='soho' else
                            'Application reference / sample-associated malware; not independent per-flow intent truth')


def audit_benign_pcap(item):
    path = ROOT/item['file']
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != item['sha256']:
        raise ValueError('Benign capture source hash mismatch')
    with path.open('rb') as file:
        snaplen = validate_header(file.read(24))
    counts = Counter(dict(parsed_ip_observations=0,port_443_hints=0,parser_returned_clienthello=0,
                          cipher_list_nonempty=0,extension_count_positive=0))
    for batch in PcapReader().read_packets(path):
        for flow, _, tls in batch:
            counts['parsed_ip_observations'] += 1
            counts['port_443_hints'] += flow.src_port == 443 or flow.dst_port == 443
            if tls:
                counts['parser_returned_clienthello'] += 1
                counts['cipher_list_nonempty'] += bool(tls.cipher_suites)
                counts['extension_count_positive'] += tls.extension_count > 0
    return dict(file=item['file'],sha256=actual,snaplen=snaplen,counts=dict(counts),
                label_scope=item['label_scope'],malicious_session_truth=False)


def audit():
    manifest = json.loads((ROOT/'data/public_manifest.json').read_text())
    integrity = []
    for item in manifest['files']:
        path = ROOT/'data/raw/tls-18336960'/item['file']
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item['sha256'] or path.stat().st_size != item['bytes']:
            raise ValueError('TLS source manifest integrity mismatch')
        integrity.append(dict(file=item['file'],bytes=path.stat().st_size,sha256=digest))
    collections = [audit_archive(ROOT/f'data/raw/tls-18336960/{name}.parquet.zip',name)
                   for name in ('winapps','malware','soho')]
    catalog = json.loads((ROOT/'data/dns_capture_catalog.json').read_text())
    benign = [audit_benign_pcap(item) for item in catalog if item['category']=='benign']
    return dict(audit_date='2026-10-12',scope='Development feasibility/visibility only, not model quality',
                tls_source=manifest['source'],licence_record=manifest['licence'],integrity=integrity,
                collections=collections,benign_capture_visibility=benign,
                mixed_captures_catalogued_not_replayed=sum(item['category']!='benign' for item in catalog),
                policy=dict(training=False,inference=False,reserved_data=False,
                            historical_test_feature_columns_read=False,soho_row_values_read=False,
                            raw_pcap_downloads=False,probes=False,decryption=False,runtime_changes=False),
                source_sha256={name:hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest()
                               for name in ('datasets/audit_encrypted_data.py','datasets/tls.py','datasets/train_tls.py',
                                            'ingest/metadata.py','ingest/protocol_parsers.py','schemas/tls_metadata.py')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    report = audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as file:
        json.dump(report,file,indent=2,allow_nan=False)
        file.write('\n')
    print(json.dumps({item['collection']:item['totals'] for item in report['collections']},indent=2))


if __name__ == '__main__':
    main()

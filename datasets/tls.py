"""Bounded, read-only Parquet adapter for completed TLS metadata.

No reconstruction of packet times or IP packet sizes from TLS record lengths.
Annotations are kept in evaluation metadata, never included in model features.
"""
import math
import zipfile
from collections import Counter
from datasets.download import ROOT

FEATURES = ['forward_bytes', 'forward_packets', 'duration_seconds',
            'forward_record_count', 'forward_record_mean', 'forward_record_cv',
            'client_cipher_count', 'client_extension_count', 'has_record_sequence']


def rows(collection):
    import pyarrow.parquet as pq
    with zipfile.ZipFile(ROOT / f'data/raw/tls-18336960/{collection}.parquet.zip') as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith('.parquet'):
                continue
            # Read individual bounded compressed members, not the entire archive.
            with archive.open(name) as file:
                parquet = pq.ParquetFile(file)
                for batch in parquet.iter_batches(batch_size=1024):
                    yield from batch.to_pylist()


def label(row, collection):
    if collection == 'winapps' and row.get('meta.application.name'):
        return 'BENIGN_REFERENCE'
    if collection == 'malware' and row.get('meta.malware.family') and not row.get('meta.system.service'):
        return 'MALWARE_RELATED'
    return 'UNLABELLED'  # SOHO and ambiguous sandbox connections stay unknown.


def vector(row):
    # Strict forward-only feature view. Signed reverse records and br/pr excluded.
    forward = [n for n in (row.get('tls.rec') or []) if n > 0]
    mean = sum(forward) / len(forward) if forward else 0
    variation = math.sqrt(sum((n - mean) ** 2 for n in forward) / len(forward)) / mean if mean else 0
    values = [row.get('bs'), row.get('ps'), row.get('td'), len(forward), mean, variation,
              len(row.get('tls.ccs') or []), len(row.get('tls.cext') or []), int(row.get('tls.rec') is not None)]
    # Core missing measurements cause rejection, not invented zero observations.
    if any(v is None or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('Missing or invalid TLS measurements')
    return [math.log1p(v) for v in values]

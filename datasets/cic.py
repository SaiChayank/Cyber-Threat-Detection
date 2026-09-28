"""Official CIC completed-flow CSV reader; not a packet-stream reconstruction."""
import csv
import io
import math
import zipfile
from datasets.download import ROOT

FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max']


def rows():
    with zipfile.ZipFile(ROOT / 'data/raw/cicids2017/MachineLearningCSV.zip') as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith('.csv'):
                continue
            with io.TextIOWrapper(archive.open(name), encoding='utf-8-sig', errors='replace', newline='') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    yield name.rsplit('/',1)[-1], {k.strip():v for k,v in row.items() if k}


def vector(row):
    values = [float(row[k]) for k in FEATURES]
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('Non-finite/negative completed-flow measurement')
    return [math.log1p(v) for v in values]

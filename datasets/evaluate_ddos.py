"""External CIC-DDoS2019 evaluation of the completed-flow baseline."""
import csv
import hashlib
import json
import math
from collections import Counter
from datasets.cic import vector
from datasets.download import ROOT


def main():
    path = ROOT/'ml/public_cic.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != path.with_suffix('.sha256').read_text().strip():
        raise ValueError('Candidate integrity mismatch')
    model = json.loads(raw)
    labels, counts, seen = Counter(), Counter(), set()
    with (ROOT/'data/raw/cicddos2019/first-csv-100000-rows.csv').open(encoding='utf-8-sig',newline='') as source:
        for original in csv.DictReader(source):
            row = {k.strip():v for k,v in original.items() if k}
            truth = row['Label'].strip()
            labels[truth] += 1
            if truth not in {'BENIGN','UDP','Syn','LDAP','MSSQL','NetBIOS','Portmap','UDPLag','UDP-lag','DrDoS_DNS','DrDoS_LDAP','DrDoS_MSSQL','DrDoS_NetBIOS','DrDoS_NTP','DrDoS_SNMP','DrDoS_SSDP','DrDoS_UDP'}:
                counts['unsupported_label'] += 1
                continue
            try:
                x = vector(row)
            except (ValueError, KeyError):
                counts['invalid'] += 1
                continue
            signature = tuple(x)
            if signature in seen:
                counts['duplicate_vectors_excluded'] += 1
                continue
            seen.add(signature)
            scores = {k:math.log(s['prior'])-.5*sum(math.log(2*math.pi*v)+(a-m)**2/v for a,m,v in zip(x,s['mean'],s['variance'])) for k,s in model['classes'].items()}
            predicted = 1/(1+math.exp(max(-700,min(700,scores['BENIGN']-scores['DDOS'])))) >= model['threshold']
            actual = truth != 'BENIGN'
            counts['tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'] += 1
    report = dict(labels=dict(labels), counts=dict(counts), recall=counts['tp']/max(1,counts['tp']+counts['fn']) if counts['tp']+counts['fn'] else None, false_positive_rate=counts['fp']/max(1,counts['fp']+counts['tn']) if counts['fp']+counts['tn'] else None, caveats=['External 100k-row prefix; selection bias, not the full release', 'Completed-flow forward-only baseline, not the streaming model', 'Missing negative/positive class metrics are null, never zero accuracy', 'Threshold fixed from source training; no test tuning'])
    (ROOT/'ml/public_ddos_evaluation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()

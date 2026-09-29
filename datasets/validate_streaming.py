"""Reproduce external validation of the deployed streaming pipeline, offline.

No training, threshold tuning, API writes, or modification of raw input files.
Run: python -m datasets.validate_streaming
"""
import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone

from datasets.domains import domains, replay_domains
from datasets.download import ROOT
from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader
from ml.model import ARTIFACT
from ml.dga import ARTIFACT as DGA_ARTIFACT, DgaModel


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def metrics(counts):
    def divide(a, b):
        return a / b if b else None
    tp, fn, fp, tn = (counts[k] for k in ('tp', 'fn', 'fp', 'tn'))
    return dict(tp=tp, fn=fn, fp=fp, tn=tn,
                precision=divide(tp, tp + fp), recall=divide(tp, tp + fn),
                false_positive_rate=divide(fp, fp + tn))


def validate_domains():
    root = ROOT / 'data/raw/umudga'
    paths = sorted(root.glob('*.txt'))
    if not paths or not (root / 'legit.txt').is_file():
        raise FileNotFoundError('UMUDGA lists including legit.txt are required')
    positives = set().union(*(set(domains(p)) for p in paths if p.stem != 'legit'))
    results, combined = [], Counter()
    for path in paths:
        pipeline, counts, seen, examples = Pipeline(), Counter(), set(), []
        actual = path.stem != 'legit'
        for i, event in enumerate(replay_domains(path)):
            if event.dns_name in seen or (not actual and event.dns_name in positives):
                continue
            seen.add(event.dns_name)
            # Isolate lexical decisions from simulated timing and 30-second alert
            # suppression. These timestamps are NOT real network observations.
            event = event.model_copy(update={'timestamp': 1700000000000 + i * 61000})
            predicted = any(a.threat_class == 'DGA_DOMAINS'
                            for a in pipeline.process(event))
            key = 'tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'
            counts[key] += 1
            if predicted != actual and len(examples) < 5:
                examples.append(event.dns_name)
        combined.update(counts)
        result = dict(family=path.stem, source_sha256=sha256(path),
                      evaluated_unique_domains=len(seen), **metrics(counts),
                      error_examples=examples)
        results.append(result)
        print('DGA', path.stem, dict(counts), flush=True)
    return dict(scope='Runtime DGA alert decisions on public strings in isolated simulated DNS events',
                families=results, combined=metrics(combined),
                caveats=['Counts are unique-domain decisions, not real network flow accuracy',
                         'Other emitted threat classes are excluded from DGA confusion counts',
                         'Only first-label lexical features currently reach the detector',
                         'Previously inspected inputs: this run is regression validation, not an untouched holdout',
                         'DGA requires first-label length >=20, entropy >=3.5 and bigram surprise >=0.8 even for an ML hit'])


def validate_captures():
    catalog = json.loads((ROOT / 'data/dns_capture_catalog.json').read_text())
    results = []
    for item in catalog:
        path = ROOT / item['file']
        if sha256(path) != item['sha256']:
            raise ValueError(f"Capture integrity mismatch: {item['id']}")
        pipeline, alerts, dns_types, ports = Pipeline(), Counter(), Counter(), Counter()
        dns_count = max_query_length = long_txt = 0
        started = time.perf_counter()
        for batch in PcapReader().read_packets(path):
            for flow, dns, tls in batch:
                event = from_packet(flow, dns, tls)
                if event.protocol == 17:
                    ports[event.dst_port] += 1
                if dns:
                    dns_count += 1
                    dns_types[str(dns.query_type)] += 1
                    max_query_length = max(max_query_length, len(dns.query_name))
                    long_txt += dns.query_type == 16 and len(dns.query_name.split('.')[0]) >= 50
                alerts.update(str(a.threat_class) for a in pipeline.process(event))
        elapsed = time.perf_counter() - started
        total = pipeline.processed
        result = dict(capture=item['id'], category=item['category'], source_sha256=item['sha256'],
                      parsed_ip_packets=total, dns_observations=dns_count,
                      dns_query_types=dict(dns_types), max_dns_query_length=max_query_length,
                      long_txt_first_labels=long_txt, top_udp_destination_ports=ports.most_common(5),
                      alerts_by_class=dict(alerts), elapsed_seconds=elapsed,
                      parsed_packets_per_second=total / elapsed,
                      telemetry=pipeline.telemetry(),
                      interpretation='Benign-reference alerts are false-positive candidates; deduplicated counts are not FPR'
                      if item['category'] == 'benign' else 'Mixed capture: no per-flow labels; recall cannot be measured')
        results.append(result)
        print('PCAP', item['id'], total, dict(alerts), flush=True)
    return results


def main():
    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                  model_sha256=sha256(ARTIFACT), model='Current synthetic-trained hybrid streaming pipeline',
                  dga_candidate_sha256=sha256(DGA_ARTIFACT) if DGA_ARTIFACT.is_file() else None,
                  dga_candidate_enabled=DgaModel().enabled,
                  runtime_source_sha256={file: sha256(ROOT / file) for file in
                                         ('detection/pipeline.py', 'features/extractor.py', 'features/rate_window.py',
                                          'ingest/protocol_parsers.py', 'ml/dga.py')},
                  umudga=validate_domains(), captures=validate_captures(),
                  limitations=['PCAP throughput includes parsing, feature extraction and inference; excludes replay pacing, persistence and UI',
                               'No malware payloads were decrypted and no monitored host was contacted',
                               'CIC and TLS completed-flow research candidates are evaluated separately; they are not runtime models'])
    path = ROOT / 'ml/streaming_validation.json'
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Saved', path, flush=True)


if __name__ == '__main__':
    main()

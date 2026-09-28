"""Extract only bounded PCAP members and validate through the real pipeline."""
import hashlib
import json
import zipfile
from collections import Counter
from datasets.download import ROOT
from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader


def main():
    root = ROOT / 'data/raw/cicdns2021'
    catalog, report = [], []
    for archive_path in sorted(root.glob('*.zip')):
        category = archive_path.name.split('-')[0]
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                if not entry.filename.lower().endswith('.pcap'):
                    continue
                if entry.file_size > 200_000_000 or entry.compress_size == 0:
                    raise ValueError('Capture member outside extraction budget')
                # Flatten to the known category and basename; no archive path traversal.
                path = root / 'pcaps' / category / entry.filename.rsplit('/',1)[-1]
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, path.open('wb') as target:
                    while chunk := source.read(65536):
                        target.write(chunk)
                sha = hashlib.sha256(path.read_bytes()).hexdigest()
                item = dict(id=category + '-' + path.stem, category=category,
                            file=str(path.relative_to(ROOT)), sha256=sha,
                            label_scope='benign reference' if category=='benign' else 'mixed attack/benign capture; per-flow labels unavailable', public_source='CICBellEXFDNS2021')
                catalog.append(item)
                pipeline, counts = Pipeline(), Counter()
                dns = events = 0
                first = last = None
                for batch in PcapReader().read_packets(path):
                    for flow, domain, tls in batch:
                        event = from_packet(flow, domain, tls)
                        first = event.timestamp if first is None else first
                        last = event.timestamp
                        events += 1
                        dns += bool(event.dns_name)
                        for alert in pipeline.process(event):
                            counts[str(alert.threat_class)] += 1
                report.append(dict(capture=item['id'], parsed_ip_packets=events, dns_observations=dns, first_timestamp=first, last_timestamp=last, alerts_by_class=dict(counts), telemetry=pipeline.telemetry(), interpretation='Benign-capture alerts are false-positive candidates' if category=='benign' else 'Alert counts only; no recall/accuracy without per-flow labels'))
                print(item['id'], events, 'IP packets;', dict(counts), flush=True)
    (ROOT/'data/dns_capture_catalog.json').write_text(json.dumps(catalog,indent=2))
    (ROOT/'ml/public_dns_evaluation.json').write_text(json.dumps(dict(scope='Unmodified synthetic-trained streaming pipeline on real PCAP; full captures; metadata only', captures=report, caveats=['No capture is used to tune the model or thresholds', 'Attack archives contain mixed traffic; not blanket positives', 'Bidirectional captured packets are individually observed; reverse-byte ratio is unavailable in this adapter', 'Source models remain synthetic-trained; results are external sanity checks, not claims of public-data accuracy']),indent=2))


if __name__ == '__main__':
    main()

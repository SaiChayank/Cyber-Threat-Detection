"""Re-freeze runtime source pins after a deliberate, reviewed runtime change.

Run: python scripts/refreeze_runtime_pins.py [--check]

Three frozen records pin runtime source bytes so silent drift is caught:
the demo manifest provenance, the feature semantic contract and the DNS
tunnelling evaluation contract (whose hash the scorer also pins). After an
intended runtime change, verify the demo traces are unchanged
(`python -m replay.demo_pack`), then run this script to re-pin those records.
It never changes model artifacts, demo traces, gates or historical evidence.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DEMO = ROOT / 'data/demo/manifest.json'
FEATURE_CONTRACT = ROOT / 'data/feature_semantic_contract.json'
DNS_CONTRACT = ROOT / 'data/dns_tunnel_evaluation_contract.json'
DNS_SCORER = ROOT / 'datasets/score_dns_tunnel.py'
# Runtime modules added after the DNS contract was first frozen.
DNS_RUNTIME_ADDITIONS = ('features/tls_session.py', 'detection/tls_indicators.py', 'detection/tls_indicators.json',
                         'features/slow_http.py', 'ingest/flow_export.py', 'features/cow_map.py', 'detection/spoof_indicators.py', 'features/slow_read.py')


def raw_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_hash(path):
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def replace_pins(path, pins, current):
    """Swap stale hashes in place so the frozen file keeps its exact formatting."""
    raw, changed = path.read_bytes(), []
    for name, old in pins.items():
        new = current(name)
        if new != old:
            if raw.count(old.encode()) != 1:
                raise ValueError(f'{path.name}: cannot locate a unique pin for {name}')
            raw = raw.replace(old.encode(), new.encode())
            changed.append(name)
    return raw, changed


def write_sidecar(path, digest):
    sidecar = path.with_suffix('.sha256')
    newline = b'\n' if sidecar.read_bytes().endswith(b'\n') else b''
    sidecar.write_bytes(digest.encode() + newline)


def refreeze(write=True):
    report = {}
    demo = json.loads(DEMO.read_text(encoding='utf-8'))
    provenance = demo['provenance']
    raw, changed = replace_pins(DEMO, {k: v['sha256'] for k, v in provenance.items()},
                                lambda n: text_hash(ROOT / n) if provenance[n]['newline_normalized'] else raw_hash(ROOT / n))
    if write and changed:
        DEMO.write_bytes(raw)
        write_sidecar(DEMO, raw_hash(DEMO))
    report['demo_manifest'] = changed

    contract = json.loads(FEATURE_CONTRACT.read_text(encoding='utf-8'))
    raw, changed = replace_pins(FEATURE_CONTRACT, contract['current_source_sha256'], lambda n: text_hash(ROOT / n))
    if write and changed:
        FEATURE_CONTRACT.write_bytes(raw)
        write_sidecar(FEATURE_CONTRACT, text_hash(FEATURE_CONTRACT))
    report['feature_contract'] = changed

    dns = json.loads(DNS_CONTRACT.read_text(encoding='utf-8'))
    sources = dns['source_sha256']
    changed = [name for name in sources if raw_hash(ROOT / name) != sources[name]]
    added = [name for name in DNS_RUNTIME_ADDITIONS if name not in sources]
    for name in changed + added:
        sources[name] = raw_hash(ROOT / name)
    if write and (changed or added):
        DNS_CONTRACT.write_text(json.dumps(dns, indent=2) + '\n', encoding='utf-8', newline='\n')
        digest = raw_hash(DNS_CONTRACT)
        write_sidecar(DNS_CONTRACT, digest)
        scorer = DNS_SCORER.read_text(encoding='utf-8')
        scorer, count = re.subn(r"CONTRACT_SHA256 = '[0-9a-f]{64}'", f"CONTRACT_SHA256 = '{digest}'", scorer)
        if count != 1:
            raise ValueError('Cannot locate the scorer contract pin')
        DNS_SCORER.write_text(scorer, encoding='utf-8', newline='\n')
    report['dns_contract'] = changed + [f'{name} (added)' for name in added]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--check', action='store_true', help='report stale pins without writing')
    args = parser.parse_args()
    report = refreeze(write=not args.check)
    print(json.dumps(report, indent=2))
    return 1 if args.check and any(report.values()) else 0


if __name__ == '__main__':
    sys.exit(main())

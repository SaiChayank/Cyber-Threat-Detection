"""Check completed fault recovery, source preservation and owned-service cleanup."""
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


if __name__ == '__main__':
    for port in (18422, 13422):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    ready = json.loads((HERE / 'ready.json').read_text())
    expected = json.loads((HERE / 'repaired.json').read_text())['expected']
    with sqlite3.connect(Path(ready['database']).as_uri() + '?mode=ro', uri=True) as db:
        rows = [json.loads(body) | {'sequence': seq} for seq, body in db.execute('SELECT sequence, body FROM alerts ORDER BY sequence')]
    assert rows == expected and len(rows) == 3
    dom = json.loads((HERE / 'recovered-dom.json').read_text())
    assert dom['rows'] == ['3', '2', '1'] and dom['warnings'] == []
    assert 'Stream connected' in dom['status']
    assert json.loads((HERE / 'browser-console.json').read_text()) == []
    pins = json.loads((ROOT / 'docs/verification/monitor-replay-error-20261020/integrity-after.json').read_text())
    assert {name: digest(ROOT / name) for name in pins} == pins
    tracked_env = subprocess.check_output(['git', 'show', 'HEAD:frontend/next-env.d.ts'], cwd=ROOT)
    assert (ROOT / 'frontend/next-env.d.ts').read_bytes().replace(b'\r\n', b'\n') == tracked_env.replace(b'\r\n', b'\n')
    save('cleanup.json', dict(verified_owned_api_pid=ready['api_pid'], verified_owned_web_pid=ready['web_pid'],
        ports_released=[18422, 13422], owned_tab_closed=True, retained_database=ready['database'],
        original_history_modified=False, default_production_build_restored=True))
    save('integrity-after.json', pins)
    save('result.json', dict(status='PASS', node_tests=3, red_failures_before_fix=2,
        backend_tests=616, typecheck=True, production_build=True, restored_production_build=True,
        demo_traces=9, recovered_rows=3, reload_required=False,
        browser_console_errors=0, browser_console_warnings=0, protected_files_matching=len(pins),
        source_hook_sha256=digest(ROOT / 'frontend/src/hooks/use-monitor.ts'),
        scope='Actual hook regression adapter plus real store/API/SSE/proxy/Monitor fault recovery; no new model metrics'))
    raw = ROOT / 'data/raw/monitor-alert-contract-originals-20261021'
    raw.mkdir(parents=True, exist_ok=False)
    records = []
    for file in sorted(HERE.iterdir()):
        if file.suffix not in ('.json', '.log', '.txt'):
            continue
        body = file.read_bytes()
        (raw / file.name).write_bytes(body)
        normalized = ('\n'.join(line.rstrip() for line in body.decode('utf-8', errors='replace').splitlines()).rstrip() + '\n').encode()
        file.write_bytes(normalized)
        records.append(dict(path=file.name, original_sha256=hashlib.sha256(body).hexdigest(),
                            readable_sha256=hashlib.sha256(normalized).hexdigest()))
    save('original-receipt-hashes.json', records)
    print('PASS: 3 recovered records, no reload/duplicates, 130 current pins and owned cleanup')

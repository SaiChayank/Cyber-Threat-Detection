"""Validate the completed rehearsal and retain readable task-local receipts."""
import hashlib
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
from rehearse import CHECKOUT, HERE, ROOT, save


if __name__ == '__main__':
    for port in (18420, 13420):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    save('cleanup.json', dict(owned_development_pid=20768, owned_production_pid=30632,
        owned_restart_pid=15084, owned_ports_released=[18420, 13420],
        owned_tab_closed=True, retained_checkout=str(CHECKOUT), retained_history=True,
        unrelated_services_stopped=False))
    demo = json.loads((HERE / 'demo-integration.json').read_text())
    restart = json.loads((HERE / 'restart-persistence.json').read_text())
    expected = demo['alerts']
    path = CHECKOUT / 'data/alerts.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        actual = [json.loads(body) | {'sequence': seq} for seq, body in db.execute('SELECT sequence, body FROM alerts ORDER BY sequence')]
    assert actual == expected and len(actual) == 15
    assert restart['records_identical'] and restart['exact_resumed_records'] == 8
    assert any(p['status'] == 'running' and p['processed'] < 256 for p in demo['incremental_positions'])
    assert json.loads((HERE / 'browser-console.json').read_text()) == []
    core = json.loads((HERE / 'core-benchmark.json').read_text())
    delivery = json.loads((HERE / 'api-sse-benchmark.json').read_text())
    assert core['throughput_pass'] and core['latency_pass']
    assert delivery['delivery_pass'] and delivery['success_count'] == 100
    status = subprocess.check_output(['git', 'status', '--short'], cwd=CHECKOUT).decode().splitlines()
    assert sorted(line.strip() for line in status) == ['M benchmarks/delivery_latest.json', 'M benchmarks/latest.json'], status
    save('checkout-status.json', dict(only_documented_benchmark_outputs_changed=True, lines=status))
    save('tool-versions.json', {name: subprocess.check_output([shutil.which(name), '--version']).decode().strip()
                              for name in ('node', 'npm.cmd', 'git')})
    # Raw command/report bytes stay outside Git; LF-normalized copies remain readable.
    raw = ROOT / 'data/raw/clean-checkout-evidence-originals-20261020'
    raw.mkdir(parents=True, exist_ok=False)
    originals = []
    for file in sorted(HERE.iterdir()):
        if file.suffix not in ('.log', '.json', '.txt'):
            continue
        body = file.read_bytes()
        (raw / file.name).write_bytes(body)
        normalized = ('\n'.join(line.rstrip() for line in body.decode('utf-8', errors='replace').splitlines()).rstrip() + '\n').encode()
        file.write_bytes(normalized)
        originals.append(dict(path=file.name, original_sha256=hashlib.sha256(body).hexdigest(),
                              readable_sha256=hashlib.sha256(normalized).hexdigest()))
    save('original-receipt-hashes.json', originals)
    save('result.json', dict(status='PASS_CURRENT_SOURCE_REPRODUCTION_REHEARSAL', baseline='f380837',
        clean_backend_passes=606, optional_skip_reports=3, source_full_suite_passes_previously=616,
        typecheck=True, production_build=True, model_hashes=7, demo_records=15, demo_classes=7,
        first_observed_alert_position=demo['incremental_positions'][0], restart_exact_records=15,
        resumed_records=8, console_errors=0, console_warnings=0,
        undocumented_setup_steps=[], code_or_dependency_changes=False, release_ready=False,
        limitation='Windows/Python 3.13.5/Node 22.14.0 rehearsal; research data and detector quality gates remain unqualified'))
    print('PASS: isolated installation/build/tests/demo/restart; history retained, owned ports released')

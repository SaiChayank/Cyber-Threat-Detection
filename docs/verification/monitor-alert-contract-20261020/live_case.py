"""Loopback storage/SSE fault fixture. No production route or dataset is modified."""
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from persistence.store import AlertStore
from tests.test_sqlite_restart import stored_alert


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def get(route):
    with urllib.request.urlopen('http://127.0.0.1:18422' + route, timeout=3) as response:
        return json.load(response)


def start():
    for port in (18422, 13422):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    folder = Path(tempfile.mkdtemp(prefix='univect-alert-contract-'))
    database = folder / 'alerts.sqlite3'
    with_db = AlertStore(database)
    first = with_db.append(stored_alert('contract-live-1'))
    with_db.close()
    env = dict(os.environ)
    env.update(API_HOST='127.0.0.1', API_PORT='18422', API_PROXY_URL='http://127.0.0.1:18422',
               WEB_PORT='13422', ALERT_DB=str(database))
    with (HERE / 'api.log').open('wb') as log:
        api = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.main:app',
            '--host', '127.0.0.1', '--port', '18422'], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        assert api.poll() is None
        try:
            if get('/api/health')['status'] == 'online':
                break
        except Exception:
            time.sleep(.1)
    else:
        raise RuntimeError('Owned API did not start')
    with (HERE / 'web.log').open('wb') as log:
        web = subprocess.Popen([shutil.which('npm.cmd') or shutil.which('npm'), 'run', 'dev'],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    save('ready.json', dict(database=str(database), api_pid=api.pid, web_pid=web.pid,
        api_port=18422, web_port=13422, initial=[first], scope='Test-only stored alert fixtures; not detector quality'))
    for _ in range(100):
        assert web.poll() is None
        try:
            with urllib.request.urlopen('http://127.0.0.1:13422/monitor', timeout=10) as response:
                if response.status == 200:
                    print('LIVE_CASE_READY', api.pid, web.pid, flush=True)
                    return
        except Exception:
            time.sleep(.2)
    raise RuntimeError('Owned Monitor did not start')


def fault():
    ready = json.loads((HERE / 'ready.json').read_text())
    store = AlertStore(ready['database'])
    try:
        second = stored_alert('contract-live-2').to_dict()
        malformed = {key: value for key, value in second.items() if key != 'confidence_score'}
        rows = []
        with store.connection:
            for payload in (malformed, stored_alert('contract-live-3').to_dict()):
                cursor = store.connection.execute(
                    'INSERT INTO alerts(alert_id,threat,body) VALUES(?,?,?)',
                    (payload['alert_id'], payload['threat_class'], json.dumps(payload)))
                rows.append(payload | {'sequence': cursor.lastrowid})
        save('fault.json', dict(missing_field='confidence_score', original_second=second,
             inserted=rows, api_delivers_malformed_object=get('/api/alerts')[1] == rows[0]))
    finally:
        store.close()
    print('MALFORMED_SECOND_AND_VALID_THIRD_PUBLISHED', flush=True)


def repair():
    ready = json.loads((HERE / 'ready.json').read_text())
    original = json.loads((HERE / 'fault.json').read_text())['original_second']
    with sqlite3.connect(ready['database']) as db:
        db.execute('UPDATE alerts SET body=? WHERE sequence=2', (json.dumps(original),))
    expected = ready['initial'] + [original | {'sequence': 2},
        json.loads((HERE / 'fault.json').read_text())['inserted'][1]]
    assert get('/api/alerts') == expected
    save('repaired.json', dict(expected=expected, exact_api_match=True,
        no_rows_deleted=True, repaired_only_disposable_second_record=True))
    print('DURABLE_RECORD_REPAIRED', flush=True)


if __name__ == '__main__':
    {'start': start, 'fault': fault, 'repair': repair}[sys.argv[1]]()

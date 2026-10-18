"""Own test processes/files; wait for explicit browser verification acknowledgement."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from tests.test_pcap_upload import capture, tcp_syn_packet


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    for port in (18519, 13519):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    pins = json.loads((HERE.parent / 'upload-storage-20261019/integrity-after.json').read_text())
    before = {name: sha(ROOT / name) for name in pins}
    assert before == pins
    save('integrity-before.json', before)
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    environment = os.environ | dict(API_HOST='127.0.0.1', API_PORT='18519',
        API_PROXY_URL='http://127.0.0.1:18519', WEB_PORT='13519', PYTHONIOENCODING='utf-8')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    processes = []
    with tempfile.TemporaryDirectory(prefix='univect-feedback-20261019-') as temp:
        owned = Path(temp)
        staging = owned / 'staging'
        staging.mkdir()
        environment |= dict(ALERT_DB=str(owned / 'alerts.sqlite3'), TEST_STAGING_DIR=str(staging),
                            TEST_TRACE=str(HERE / 'storage-trace.jsonl'))
        (owned / 'valid.pcap').write_bytes(capture(tcp_syn_packet()))
        (owned / 'invalid.pcap').write_bytes(b'Invalid classic-PCAP fixture; no packets')
        save('fixture-paths.json', dict(valid=str(owned / 'valid.pcap'),
             invalid=str(owned / 'invalid.pcap'), database=str(owned / 'alerts.sqlite3'),
             fixture_scope='Generated transport unit fixtures, not detector evaluation'))
        with (HERE / 'build.log').open('wb') as log:
            result = subprocess.run([npm, 'run', 'build'], cwd=ROOT, env=environment,
                                    stdout=log, stderr=subprocess.STDOUT)
        assert result.returncode == 0, 'Configured build failed'
        try:
            for label, command in [('api', [sys.executable, '-B', HERE / 'fault_server.py']),
                                   ('web', [npm, 'start'])]:
                if label == 'web':
                    wait_url(opener, 'http://127.0.0.1:18519/api/health', processes[0])
                with (HERE / f'{label}.log').open('wb') as log:
                    process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=environment,
                        stdout=log, stderr=subprocess.STDOUT,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                processes.append(process)
            wait_url(opener, 'http://127.0.0.1:13519/monitor', processes[-1])
            save('ready.json', dict(url='http://127.0.0.1:13519/monitor',
                 pids=[p.pid for p in processes], fault='One allocation ENOSPC only'))
            print('MONITOR_FEEDBACK_READY', flush=True)
            deadline = time.monotonic() + 600
            while not (HERE / 'browser-ack.json').exists():
                assert all(p.poll() is None for p in processes), 'Owned service exited'
                if time.monotonic() > deadline:
                    raise TimeoutError('Browser verification acknowledgement timeout')
                time.sleep(.5)
            with opener.open('http://127.0.0.1:13519/api/telemetry') as response:
                state = json.load(response)
            with opener.open('http://127.0.0.1:13519/api/alerts') as response:
                alerts = json.load(response)
            assert state['processed'] == 1 and state['replay_status'] == 'complete'
            assert alerts == [] and not list(staging.iterdir())
            save('final-api.json', dict(telemetry=state, alerts=alerts, staged_files_remaining=0))
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
                    process.wait(timeout=20)
    after = {name: sha(ROOT / name) for name in before}
    assert after == before
    save('integrity-after.json', after)
    print('MONITOR_FEEDBACK_PASS', flush=True)


def wait_url(opener, url, process):
    for _ in range(90):
        assert process.poll() is None, 'Owned service exited during startup'
        try:
            with opener.open(url, timeout=3) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(.5)
    raise RuntimeError('Owned service readiness timeout')


if __name__ == '__main__':
    main()

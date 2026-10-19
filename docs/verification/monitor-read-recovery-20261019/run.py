"""Own isolated verification processes and restore the normal build on exit."""
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

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import httpx
from tests.test_sse_resume import event


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_ready(client, url, process):
    for _ in range(90):
        assert process.poll() is None, 'Owned service exited'
        try:
            if client.get(url).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(.3)
    raise TimeoutError('Owned service readiness timeout')


def build(npm, environment, label):
    with (HERE / (label + '.log')).open('wb') as log:
        result = subprocess.run([npm, 'run', 'build'], cwd=ROOT, env=environment,
                                stdout=log, stderr=subprocess.STDOUT)
    save(label + '.json', dict(exit_code=result.returncode))
    assert result.returncode == 0, label


def main():
    for port in (18529, 13529):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    pins = json.loads((HERE.parent/'sqlite-read-recovery-20261019/integrity-after.json').read_text())
    before = {p:digest(ROOT/p) for p in pins}
    assert before == pins
    save('integrity-before.json', before)
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    environment = os.environ | dict(API_HOST='127.0.0.1', API_PORT='18529',
        API_PROXY_URL='http://127.0.0.1:18529', WEB_PORT='13529', PYTHONIOENCODING='utf-8')
    processes=[]
    try:
        build(npm, environment, 'isolated-build')
        with tempfile.TemporaryDirectory(prefix='univect-monitor-read-') as directory:
            owned=Path(directory)
            environment |= dict(ALERT_DB=str(owned/'history.sqlite3'),
                TEST_READ_MARKER=str(owned/'read-fault'), TEST_READ_TRACE=str(HERE/'api-trace.jsonl'))
            with httpx.Client(trust_env=False, timeout=3) as client:
                try:
                    for label, command in [('api',[sys.executable,'-B',HERE/'fault_server.py']),
                                           ('web',[npm,'start'])]:
                        with (HERE/(label+'.log')).open('wb') as log:
                            process=subprocess.Popen(list(map(str,command)),cwd=ROOT,env=environment,
                                stdout=log,stderr=subprocess.STDOUT,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                        processes.append(process)
                        wait_ready(client,'http://127.0.0.1:18529/api/health' if label=='api'
                                   else 'http://127.0.0.1:13529/monitor',process)
                    accepted=[]
                    for index in range(2):
                        response=client.post('http://127.0.0.1:13529/api/events',json=event(index))
                        response.raise_for_status(); assert len(response.json())==1
                        accepted.extend(response.json())
                    save('accepted.json',accepted)
                    save('ready.json',dict(url='http://127.0.0.1:13529/monitor',
                        database=str(owned/'history.sqlite3'),marker=str(owned/'read-fault'),
                        pids=[p.pid for p in processes],initial_alerts=2))
                    print('MONITOR_READ_READY',flush=True)
                    deadline=time.monotonic()+1200
                    while not (HERE/'browser-ack.json').exists():
                        assert all(p.poll() is None for p in processes),'Owned service exited'
                        if time.monotonic()>deadline:raise TimeoutError('Browser acknowledgement timeout')
                        time.sleep(.5)
                    accepted=json.loads((HERE/'accepted.json').read_text())
                    response=client.get('http://127.0.0.1:13529/api/alerts')
                    response.raise_for_status(); assert response.json()==accepted
                    assert len(accepted)==8
                    save('final-api.json',dict(alerts=response.json(),
                        telemetry=client.get('http://127.0.0.1:13529/api/telemetry').json()))
                finally:
                    for process in reversed(processes):
                        if process.poll() is None:
                            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],check=True,
                                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            process.wait(timeout=20)
            from persistence.store import AlertStore
            store=AlertStore(owned/'history.sqlite3')
            try:assert store.list()==accepted
            finally:store.close()
            save('restart-history.json',dict(exact_records=8,passed=True))
    finally:
        build(npm, os.environ.copy(), 'restored-default-build')
    after={p:digest(ROOT/p) for p in before}; assert after==before
    save('integrity-after.json',after)
    print('MONITOR_READ_PASS',flush=True)


if __name__=='__main__':main()

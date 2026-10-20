"""Scoped browser rehearsal with owned services and restored production build."""
import importlib.util
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
from persistence.store import AlertStore
from tests.test_replay_controls import alert_event

spec = importlib.util.spec_from_file_location('monitor_helpers', HERE.parent/'monitor-read-recovery-20261019/run.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
helpers.HERE = HERE


def main():
    for port in (18533, 13533):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    pins = json.loads((HERE.parent/'udp-alternative-sources-20261019/protected-hashes.json').read_text())
    before = {name:helpers.digest(ROOT/name) for name in pins}
    assert {name for name in pins if before[name] != pins[name]} == {'data/demo/manifest.json','data/demo/manifest.sha256'}
    helpers.save('integrity-before.json', before)
    environment = os.environ | dict(API_HOST='127.0.0.1',API_PORT='18533',
        API_PROXY_URL='http://127.0.0.1:18533',WEB_PORT='13533',PYTHONIOENCODING='utf-8')
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    processes=[]
    try:
        helpers.build(npm, environment, 'isolated-build')
        with tempfile.TemporaryDirectory(prefix='univect-replay-error-') as directory:
            owned=Path(directory)
            environment |= dict(ALERT_DB=str(owned/'history.sqlite3'),TEST_REPLAY_MARKER=str(owned/'source-fault'))
            with httpx.Client(trust_env=False,timeout=3) as client:
                try:
                    for label, command in [('api',[sys.executable,'-B',HERE/'fault_server.py']),('web',[npm,'start'])]:
                        with (HERE/(label+'.log')).open('wb') as log:
                            process=subprocess.Popen(list(map(str,command)),cwd=ROOT,env=environment,
                                stdout=log,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                        processes.append(process)
                        helpers.wait_ready(client,'http://127.0.0.1:18533/api/health' if label=='api' else 'http://127.0.0.1:13533/monitor',process)
                    saved=[]
                    for index in (0,1):
                        response=client.post('http://127.0.0.1:13533/api/events',json=alert_event(index))
                        response.raise_for_status();saved.extend(response.json())
                    helpers.save('ready.json',dict(url='http://127.0.0.1:13533/monitor',marker=str(owned/'source-fault'),initial_alerts=saved))
                    print('MONITOR_REPLAY_READY',flush=True)
                    deadline=time.monotonic()+900
                    while not (HERE/'browser-ack.json').exists():
                        assert all(p.poll() is None for p in processes)
                        if time.monotonic()>deadline:raise TimeoutError('Browser verification timeout')
                        time.sleep(.5)
                    rows=client.get('http://127.0.0.1:13533/api/alerts').json()
                    state=client.get('http://127.0.0.1:13533/api/telemetry').json()
                    assert len(rows)==5 and rows[:2]==saved
                    assert state['replay_status']=='complete' and state['replay_error'] is None and state['processed']==32
                    helpers.save('final-api.json',dict(alerts=rows,telemetry=state))
                finally:
                    for process in reversed(processes):
                        if process.poll() is None:
                            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            process.wait(timeout=20)
            store=AlertStore(owned/'history.sqlite3')
            try:assert store.list()==rows
            finally:store.close()
            helpers.save('durable-check.json',dict(exact_records=5,passed=True))
    finally:
        helpers.build(npm,os.environ.copy(),'restored-default-build')
    after={name:helpers.digest(ROOT/name) for name in before};assert after==before
    helpers.save('integrity-after.json',after)
    print('MONITOR_REPLAY_PASS',flush=True)


if __name__=='__main__':main()

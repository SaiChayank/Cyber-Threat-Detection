"""Stdlib-only controller for README commands in a genuinely separate checkout."""
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
CHECKOUT = Path(tempfile.gettempdir()) / 'univect-clean-20261018-4e92b3b'
ENV = dict(os.environ)
for key in ('VIRTUAL_ENV', 'PYTHONPATH', 'PYTHONHOME', 'PYTHON_EXECUTABLE',
            'API_HOST', 'API_PORT', 'API_PROXY_URL', 'WEB_PORT', 'ALERT_DB'):
    ENV.pop(key, None)
ENV['PYTHONIOENCODING'] = 'utf-8'
NPM = shutil.which('npm.cmd') or shutil.which('npm')


def save(name, value):
    (HERE / name).write_bytes((json.dumps(value, indent=2) + '\n').encode())


def run(name, args, cwd=CHECKOUT, timeout=600):
    started = time.monotonic()
    with (HERE / f'{name}.log').open('wb') as log:
        result = subprocess.run(list(map(str, args)), cwd=cwd, env=ENV,
                                stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    record = dict(command=list(map(str, args)), cwd=str(cwd), exit_code=result.returncode,
                  elapsed_seconds=time.monotonic() - started)
    save(f'{name}-command.json', record)
    print(name, result.returncode, flush=True)
    if result.returncode:
        raise RuntimeError(f'{name} failed: see {name}.log')
    return record


def launch(mode, label):
    out = (HERE / f'{label}.log').open('wb')
    process = subprocess.Popen([NPM, 'run', mode] if mode == 'dev' else [NPM, 'start'],
                               cwd=CHECKOUT, env=ENV, stdout=out, stderr=subprocess.STDOUT)
    save('owned-process.json', dict(pid=process.pid, mode=mode, label=label,
                                   checkout=str(CHECKOUT)))
    out.close()
    return process


def wait_ready(process, timeout=300):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError('Owned launcher exited before readiness')
        try:
            with opener.open('http://127.0.0.1:18418/api/health', timeout=2) as response:
                health = json.load(response)
            with opener.open('http://127.0.0.1:13418/monitor', timeout=20) as response:
                status = response.status
            if health['architecture'] == 'unidirectional-passive-monitoring' and status == 200:
                return health
        except Exception:
            time.sleep(1)
    raise RuntimeError('Readiness timeout')


def stop(pid):
    subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def prepare():
    assert not CHECKOUT.exists(), 'Refuse reuse of a pre-existing checkout'
    for port in (18418, 13418):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    original = json.loads((ROOT / 'docs/verification/uma-header-transport-20261018/integrity-after.json').read_text())
    save('integrity-before.json', original)
    run('clone', ['git', 'clone', '--no-local', '--no-hardlinks', '--no-checkout', ROOT, CHECKOUT], cwd=ROOT)
    run('checkout', ['git', '-c', 'core.autocrlf=true', 'checkout', '--detach', '4e92b3b'])
    assert not any((CHECKOUT / item).exists() for item in ('.venv', 'node_modules', '.env', 'data/alerts.sqlite3', 'data/raw'))
    save('isolation.json', dict(checkout=str(CHECKOUT), baseline='4e92b3b',
                               copied_environment=False, copied_database=False,
                               copied_node_modules=False, copied_raw_data=False))
    (CHECKOUT / '.env').write_text('API_HOST=127.0.0.1\nAPI_PORT=18418\nAPI_PROXY_URL=http://127.0.0.1:18418\nWEB_PORT=13418\nALERT_DB=data/alerts.sqlite3\n')
    run('npm-install', [NPM, 'install'])
    process = launch('dev', 'development-start')
    try:
        save('development-ready.json', wait_ready(process))
    finally:
        if process.poll() is None:
            stop(process.pid)
    print('PREPARATION_PASS', flush=True)


def verify():
    py = CHECKOUT / '.venv/Scripts/python.exe'
    run('pip-check', [py, '-m', 'pip', 'check'])
    run('python-packages', [py, '-m', 'pip', 'list', '--format=json'])
    run('npm-packages', [NPM, 'ls', '--depth=0'])
    run('backend-tests', [py, '-m', 'pytest', '-q'], timeout=1200)
    run('demo-preflight', [py, '-m', 'replay.demo_pack'])
    run('typecheck', [NPM, 'run', 'typecheck'])
    run('production-build', [NPM, 'run', 'build'])
    run('core-benchmark', [py, '-m', 'benchmarks.run', '--events', '20000'])
    shutil.copyfile(CHECKOUT / 'benchmarks/latest.json', HERE / 'core-benchmark.json')
    run('api-sse-benchmark', [py, '-m', 'benchmarks.delivery', '--events', '100'])
    shutil.copyfile(CHECKOUT / 'benchmarks/delivery_latest.json', HERE / 'api-sse-benchmark.json')
    run('offline-demo', [py, '-m', 'replay.cli', 'data/demo/all.jsonl', '--speed', '20'])
    process = launch('start', 'production-start')
    save('production-ready.json', wait_ready(process))
    print('PRODUCTION_READY', process.pid, flush=True)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    {'prepare': prepare, 'verify': verify}[sys.argv[1]]()

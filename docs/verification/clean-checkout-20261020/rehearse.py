"""Reuse the existing rehearsal controller, with a new checkout and documented ports."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECKOUT = Path(tempfile.gettempdir()) / 'univect-clean-20261020-f380837'
spec = importlib.util.spec_from_file_location('prior_rehearsal', HERE.parent / 'clean-checkout-20261018/rehearse.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.HERE = HERE
prior.CHECKOUT = CHECKOUT
save = prior.save
NPM = prior.NPM


def run(name, args, timeout=600):
    return prior.run(name, args, cwd=CHECKOUT, timeout=timeout)


def ready(process):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        assert process.poll() is None, 'Owned launcher exited before readiness'
        try:
            with opener.open('http://127.0.0.1:18420/api/health', timeout=2) as response:
                health = json.load(response)
            with opener.open('http://127.0.0.1:13420/monitor', timeout=20) as response:
                assert response.status == 200
            assert health['architecture'] == 'unidirectional-passive-monitoring'
            return health
        except Exception:
            time.sleep(1)
    raise RuntimeError('Owned-server readiness timeout')


def prepare():
    assert not CHECKOUT.exists(), 'Preserve all earlier clean environments'
    for port in (18420, 13420):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    prior.run('clone', ['git', 'clone', '--no-local', '--no-hardlinks', '--no-checkout', ROOT, CHECKOUT], cwd=ROOT)
    run('checkout', ['git', '-c', 'core.autocrlf=true', 'checkout', '--detach', 'f380837'])
    absent = ('.venv', 'node_modules', '.env', 'data/alerts.sqlite3', 'data/raw')
    assert not any((CHECKOUT / name).exists() for name in absent)
    save('isolation.json', dict(checkout=str(CHECKOUT), baseline='f380837', initially_absent=list(absent), copied_developer_environment=False))
    content = (CHECKOUT / '.env.example').read_text().replace('API_PORT=8000', 'API_PORT=18420').replace(
        'http://127.0.0.1:8000', 'http://127.0.0.1:18420').replace('WEB_PORT=3000', 'WEB_PORT=13420')
    (CHECKOUT / '.env').write_bytes(content.encode())
    run('npm-install', [NPM, 'install'])
    process = prior.launch('dev', 'development-start')
    try:
        save('development-ready.json', ready(process))
    finally:
        if process.poll() is None:
            prior.stop(process.pid)
    print('PREPARATION_PASS', flush=True)


def verify():
    py = CHECKOUT / '.venv/Scripts/python.exe'
    run('pip-check', [py, '-m', 'pip', 'check'])
    run('python-packages', [py, '-m', 'pip', 'list', '--format=json'])
    run('npm-packages', [NPM, 'ls', '--depth=0'])
    run('environment', [py, '-c', 'import sys,json,platform; print(json.dumps(dict(python=sys.version,prefix=sys.prefix,base_prefix=sys.base_prefix,platform=platform.platform())))'])
    assert 'include-system-site-packages = false' in (CHECKOUT / '.venv/pyvenv.cfg').read_text()
    run('backend-tests', [py, '-m', 'pytest', '-q', '-rs'], timeout=1200)
    run('demo-preflight', [py, '-m', 'replay.demo_pack'])
    run('typecheck', [NPM, 'run', 'typecheck'])
    run('production-build', [NPM, 'run', 'build'])
    run('core-benchmark', [py, '-m', 'benchmarks.run', '--events', '20000'])
    (HERE / 'core-benchmark.json').write_bytes((CHECKOUT / 'benchmarks/latest.json').read_bytes())
    run('api-sse-benchmark', [py, '-m', 'benchmarks.delivery', '--events', '100'])
    (HERE / 'api-sse-benchmark.json').write_bytes((CHECKOUT / 'benchmarks/delivery_latest.json').read_bytes())
    run('offline-demo', [py, '-m', 'replay.cli', 'data/demo/all.jsonl', '--speed', '20'])
    process = prior.launch('start', 'production-start')
    save('production-ready.json', ready(process))
    print('PRODUCTION_READY', process.pid, flush=True)


def restart_start():
    for port in (18420, 13420):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    process = prior.launch('start', 'production-restart')
    save('production-restart-ready.json', ready(process))
    print('PRODUCTION_RESTART_READY', process.pid, flush=True)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    {'prepare': prepare, 'verify': verify, 'restart-start': restart_start}[sys.argv[1]]()

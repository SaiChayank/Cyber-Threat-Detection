"""Capture source-local regressions without modifying historical benchmark reports."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NPM = shutil.which('npm.cmd') or shutil.which('npm')


def run(label, command):
    started = time.monotonic()
    completed = subprocess.run(list(map(str, command)), cwd=ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = completed.stdout.decode('utf-8', errors='replace')
    output = '\n'.join(line.rstrip() for line in output.splitlines()).rstrip() + '\n'
    (HERE / f'{label}.log').write_bytes(output.encode())
    record = dict(command=list(map(str, command)), exit_code=completed.returncode,
                  elapsed_seconds=time.monotonic() - started)
    (HERE / f'{label}-command.json').write_bytes((json.dumps(record, indent=2) + '\n').encode())
    print(label, completed.returncode, flush=True)
    if completed.returncode:
        raise SystemExit(completed.returncode)


if __name__ == '__main__':
    stage = sys.argv[1]
    if stage == 'backend':
        run('backend-tests', [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'frontend':
        run('typecheck', [NPM, 'run', 'typecheck'])
        run('production-build', [NPM, 'run', 'build'])
    elif stage == 'delivery':
        run('demo-preflight', [sys.executable, '-B', '-m', 'replay.demo_pack'])
        run('delivery', [sys.executable, '-B', '-m', 'benchmarks.delivery', '--events', '100',
                         '--output', HERE / 'delivery.json'])
    else:
        raise SystemExit('Unknown verification stage')

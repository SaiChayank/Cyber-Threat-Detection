"""Use the existing verification runner, preserving each task's evidence."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('checks', HERE.parent / 'cursor-validation-20261019/run_checks.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE = HERE

if __name__ == '__main__':
    if sys.argv[1] == 'targeted':
        checks.run('green-tests', ['node', '--test', 'tests/frontend/monitor-alert-recovery.test.cjs'])
    else:
        sys.argv = [sys.argv[0], sys.argv[1]]
        if sys.argv[1] == 'backend':
            checks.run('backend-tests', [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'])
        elif sys.argv[1] == 'frontend':
            checks.run('typecheck', [checks.NPM, 'run', 'typecheck'])
            checks.run('production-build', [checks.NPM, 'run', 'build'])
        elif sys.argv[1] == 'demo':
            checks.run('demo-preflight', [sys.executable, '-B', '-m', 'replay.demo_pack'])
        else:
            raise SystemExit('Unknown check stage')

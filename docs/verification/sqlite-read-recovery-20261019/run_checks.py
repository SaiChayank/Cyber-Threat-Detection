"""Reuse the existing runner without overwriting historical evidence."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
helper = HERE.parent / 'cursor-validation-20261019/run_checks.py'
spec = importlib.util.spec_from_file_location('read_recovery_checks', helper)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE = HERE

if __name__ == '__main__':
    stage = sys.argv[1]
    if stage == 'red':
        checks.run('red-tests', [sys.executable, '-B', '-m', 'pytest',
            'tests/test_sqlite_read_recovery.py', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'targeted':
        checks.run('targeted-tests', [sys.executable, '-B', '-m', 'pytest',
            'tests/test_sqlite_read_recovery.py', 'tests/test_sqlite_restart.py',
            'tests/test_sse_resume.py', 'tests/test_alert_cursor_validation.py',
            'tests/test_event_recovery.py', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'backend':
        checks.run('backend-tests', [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'frontend':
        checks.run('typecheck', [checks.NPM, 'run', 'typecheck'])
        checks.run('production-build', [checks.NPM, 'run', 'build'])
    elif stage == 'delivery':
        checks.run('demo-preflight', [sys.executable, '-B', '-m', 'replay.demo_pack'])
        checks.run('delivery', [sys.executable, '-B', '-m', 'benchmarks.delivery', '--events', '100',
                                '--output', HERE / 'delivery.json'])
    else:
        raise SystemExit('Unknown verification stage')

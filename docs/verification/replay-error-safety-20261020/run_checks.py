"""Reuse logged checks; never replace prior task reports."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('replay_error_checks', HERE.parent / 'cursor-validation-20261019/run_checks.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE = HERE

if __name__ == '__main__':
    stage = sys.argv[1]
    if stage == 'red':
        checks.run('red-tests', [sys.executable, '-B', '-m', 'pytest',
            'tests/test_replay_error_safety.py', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'targeted':
        checks.run('targeted-tests', [sys.executable, '-B', '-m', 'pytest',
            'tests/test_replay_error_safety.py', 'tests/test_replay_controls.py',
            'tests/test_pcap_upload.py', 'tests/test_upload_storage_failures.py',
            '-q', '-p', 'no:cacheprovider'])
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
        raise SystemExit('Unknown stage')

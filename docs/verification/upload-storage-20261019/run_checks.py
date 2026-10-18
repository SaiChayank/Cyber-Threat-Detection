"""Reuse the existing evidence runner, with a new output directory only."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
helper = HERE.parent / 'cursor-validation-20261019/run_checks.py'
spec = importlib.util.spec_from_file_location('prior_check_runner', helper)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE = HERE  # Never overwrite a frozen earlier run's logs.

if __name__ == '__main__':
    stage = sys.argv[1]
    if stage == 'backend':
        checks.run('backend-tests', [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'])
    elif stage == 'frontend':
        checks.run('typecheck', [checks.NPM, 'run', 'typecheck'])
        checks.run('production-build', [checks.NPM, 'run', 'build'])
    elif stage == 'delivery':
        checks.run('demo-preflight', [sys.executable, '-B', '-m', 'replay.demo_pack'])
        checks.run('delivery', [sys.executable, '-B', '-m', 'benchmarks.delivery', '--events', '100',
                                '--output', HERE / 'delivery.json'])
    elif stage == 'targeted':
        checks.run('targeted-tests', [sys.executable, '-B', '-m', 'pytest',
            'tests/test_upload_storage_failures.py', 'tests/test_pcap_upload.py',
            'tests/test_replay_controls.py', 'tests/test_event_recovery.py', '-q', '-p', 'no:cacheprovider'])
    else:
        raise SystemExit('Unknown stage')

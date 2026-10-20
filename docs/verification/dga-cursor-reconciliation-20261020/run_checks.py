"""Record the existing narrow DGA safeguard suite, without training or intake reads."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('checks', HERE.parent / 'cursor-validation-20261019/run_checks.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE = HERE

if __name__ == '__main__':
    checks.run('integrity-check', [sys.executable, '-B', HERE / 'verify.py'])
    checks.run('targeted-tests', [sys.executable, '-B', '-m', 'pytest',
        'tests/test_dga_positive_intake.py', 'tests/test_dga_source_acquisition.py',
        'tests/test_dga_candidate.py', 'tests/test_dga_diagnostic.py',
        '-q', '-p', 'no:cacheprovider'])

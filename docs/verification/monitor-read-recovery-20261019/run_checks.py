"""Capture relevant existing regressions in this verification directory only."""
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
helper=HERE.parent/'cursor-validation-20261019/run_checks.py'
spec=importlib.util.spec_from_file_location('monitor_read_checks',helper)
checks=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE=HERE

if __name__=='__main__':
    if sys.argv[1]=='tests':
        checks.run('targeted-tests',[sys.executable,'-B','-m','pytest',
            'tests/test_sqlite_read_recovery.py','tests/test_sqlite_restart.py',
            'tests/test_sse_resume.py','tests/test_alert_cursor_validation.py',
            '-q','-p','no:cacheprovider'])
    elif sys.argv[1]=='typecheck':
        checks.run('typecheck',[checks.NPM,'run','typecheck'])
    else:raise SystemExit('Unknown stage')

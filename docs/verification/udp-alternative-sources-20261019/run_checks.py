"""Record source-catalogue regressions without modifying earlier reports."""
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
helper=HERE.parent/'cursor-validation-20261019/run_checks.py'
spec=importlib.util.spec_from_file_location('udp_alternative_checks',helper)
checks=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.HERE=HERE

if __name__=='__main__':
    if sys.argv[1]=='targeted':
        checks.run('targeted-tests',[sys.executable,'-B','-m','pytest',
            'tests/test_udp_archive_catalogue.py','tests/test_udp_flood.py','tests/test_udp_observability.py',
            '-q','-p','no:cacheprovider'])
    elif sys.argv[1]=='catalogue':
        checks.run('guarded-catalogue',[sys.executable,'-B',HERE/'catalogue_netslab.py'])
    else:raise SystemExit('Unknown verification stage')

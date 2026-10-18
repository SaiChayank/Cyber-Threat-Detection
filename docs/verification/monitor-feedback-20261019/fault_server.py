"""Owned test entry point: real API, one controlled staging-allocation failure."""
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from backend import application
import uvicorn

STAGING = Path(os.environ['TEST_STAGING_DIR'])
TRACE = Path(os.environ['TEST_TRACE'])
remaining_failure = True
real_create = tempfile.NamedTemporaryFile


def append_trace(record):
    with TRACE.open('a', encoding='utf-8') as output:
        output.write(json.dumps(record) + '\n')


def test_temporary_file(*args, **kwargs):
    global remaining_failure
    if remaining_failure:
        remaining_failure = False
        append_trace(dict(stage='allocate', injected_errno=errno.ENOSPC))
        raise OSError(errno.ENOSPC, 'Controlled test storage error', '/private/test/staging')
    file = real_create(*args, dir=STAGING, **kwargs)
    append_trace(dict(stage='allocate', actual_path=file.name))
    return file


application.tempfile = SimpleNamespace(NamedTemporaryFile=test_temporary_file)

if __name__ == '__main__':
    uvicorn.run(application.app, host='127.0.0.1', port=18519)

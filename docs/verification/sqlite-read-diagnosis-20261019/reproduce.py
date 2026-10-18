"""Bounded read-failure diagnosis only; no product code/DB/model changes."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
from backend.application import app
from tests.test_sqlite_restart import ddos_event

HERE = Path(__file__).resolve().parent


def main():
    pin_file = ROOT / 'docs/verification/monitor-feedback-20261019/integrity-after.json'
    pins = json.loads(pin_file.read_text())
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert {name: sha(ROOT / name) for name in pins} == pins
    old = os.environ.get('ALERT_DB')
    cases = []
    with tempfile.TemporaryDirectory(prefix='univect-read-diagnosis-') as temp:
        os.environ['ALERT_DB'] = str(Path(temp) / 'isolated.sqlite3')
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                original = client.post('/api/events', json=ddos_event(0)).json()
                assert len(original) == 1
                for route, operation, expected in [('/api/alerts', 'list', 500),
                        ('/api/telemetry', 'summary', 500), ('/api/stream', 'list', 200)]:
                    fault = sqlite3.OperationalError('Controlled read failure /private/test/history')
                    with patch.object(app.state.store, operation, side_effect=fault):
                        response = client.get(route)
                    assert response.status_code == expected
                    assert client.get('/api/alerts').json() == original
                    cases.append(dict(route=route, injected_error=type(fault).__name__,
                         response_status=response.status_code,
                         successful_sse_headers_before_failure=route == '/api/stream',
                         original_alert_recovers_unchanged=True))
                assert client.get('/api/health').status_code == 200
        finally:
            if old is None:
                os.environ.pop('ALERT_DB', None)
            else:
                os.environ['ALERT_DB'] = old
    assert {name: sha(ROOT / name) for name in pins} == pins
    result = dict(scope='Controlled SQLite read exceptions only, not physical disk corruption',
         baseline='09e97ff', cases=cases, diagnostic_dod_passed=True,
         implementation_fix_applied=False, protected_files_unchanged=len(pins),
         source_api_sha256=sha(ROOT / 'backend/application.py'), release_ready=False)
    (HERE / 'result.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print(json.dumps(result))


if __name__ == '__main__':
    main()

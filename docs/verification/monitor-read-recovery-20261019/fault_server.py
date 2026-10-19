"""Test-only controlled reads and transparent ASGI trace; product app unchanged."""
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from persistence.store import AlertStore
from backend.application import app
import uvicorn

MARKER = Path(os.environ['TEST_READ_MARKER'])
TRACE = Path(os.environ['TEST_READ_TRACE'])


def trace(value):
    with TRACE.open('a', encoding='utf-8') as output:
        output.write(json.dumps(value) + '\n')


for operation in ('list', 'summary'):
    original = getattr(AlertStore, operation)
    def controlled_read(self, *args, _original=original, _operation=operation, **kwargs):
        if MARKER.exists():
            trace(dict(kind='injected_read_error', operation=_operation))
            raise sqlite3.OperationalError('Controlled read fault /private/test/history.sqlite3')
        return _original(self, *args, **kwargs)
    setattr(AlertStore, operation, controlled_read)


async def traced_app(scope, receive, send):
    if scope['type'] != 'http':
        return await app(scope, receive, send)
    headers = dict(scope['headers'])
    request = dict(path=scope['path'], query=scope['query_string'].decode(),
                   last_event_id=headers.get(b'last-event-id', b'').decode())
    async def traced_send(message):
        if message['type'] == 'http.response.start':
            trace(dict(kind='http_status', status=message['status'], **request))
        if message['type'] == 'http.response.body' and scope['path'] == '/api/stream':
            for line in message.get('body', b'').decode().splitlines():
                if line.startswith('data: '):
                    row = json.loads(line[6:])
                    trace(dict(kind='sse_record', sequence=row['sequence'], alert_id=row['alert_id'], **request))
            if not message.get('more_body', False):
                trace(dict(kind='sse_eof', **request))
        await send(message)
    await app(scope, receive, traced_send)


if __name__ == '__main__':
    uvicorn.run(traced_app, host='127.0.0.1', port=18529, log_level='warning', access_log=False)

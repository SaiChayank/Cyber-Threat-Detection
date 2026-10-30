"""SQLite alert persistence with bounded query responses."""
import json
import sqlite3
from pathlib import Path


class AlertStore:
    def __init__(self, path='data/alerts.sqlite3'):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute('PRAGMA journal_mode=WAL')
        # WAL + NORMAL: a committed alert survives application crashes and restarts and the database is never
        # corrupted; only an operating-system crash or power loss can lose the last few commits. FULL would
        # sync the disk on every alert (about 30-45% lower throughput, p95 about 3x higher).
        self.connection.execute('PRAGMA synchronous=NORMAL')
        self.connection.execute('CREATE TABLE IF NOT EXISTS alerts (sequence INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT UNIQUE, threat TEXT, body TEXT)')
        self.connection.commit()

    def append(self, alert):
        return self.append_many([alert])[0]

    def append_many(self, alerts):
        """Persist all alerts for one observation, or roll back the entire batch."""
        rows = []
        with self.connection:
            for alert in alerts:
                body = alert.to_dict()
                cursor = self.connection.execute('INSERT INTO alerts(alert_id, threat, body) VALUES (?, ?, ?)',
                                                 (alert.alert_id, alert.threat_class, json.dumps(body)))
                rows.append(body | {'sequence': cursor.lastrowid})
        return rows

    def list(self, after=0, limit=200, threat=None, newest=False):
        condition = 'sequence > ?'
        params = [after]
        if threat:
            condition += ' AND threat = ?'
            params.append(threat)
        params.append(limit)
        order = 'DESC' if newest else 'ASC'
        rows = self.connection.execute(f'SELECT sequence, body FROM alerts WHERE {condition} ORDER BY sequence {order} LIMIT ?', params).fetchall()
        records = []
        for seq, body in rows:
            try:
                record = json.loads(body)
                if not isinstance(record, dict):
                    raise ValueError('Stored alert body must be a JSON object')
            except (ValueError, TypeError) as exc:
                # Treat unreadable durable data like other storage read failures.
                # Never return a partial batch, discard a row or fabricate data.
                raise sqlite3.DatabaseError('Stored alert data is unreadable') from exc
            records.append(record | {'sequence': seq})
        return records

    def summary(self):
        return dict(self.connection.execute('SELECT threat, COUNT(*) FROM alerts GROUP BY threat').fetchall())

    def close(self):
        self.connection.close()

"""SQLite alert persistence with bounded query responses."""
import json
import sqlite3
from pathlib import Path


class AlertStore:
    def __init__(self, path='data/alerts.sqlite3'):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('CREATE TABLE IF NOT EXISTS alerts (sequence INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT UNIQUE, threat TEXT, body TEXT)')
        self.connection.commit()

    def append(self, alert):
        body = alert.to_dict()
        cursor = self.connection.execute('INSERT INTO alerts(alert_id, threat, body) VALUES (?, ?, ?)',
                                         (alert.alert_id, alert.threat_class, json.dumps(body)))
        self.connection.commit()
        return body | {'sequence': cursor.lastrowid}

    def list(self, after=0, limit=200, threat=None, newest=False):
        condition = 'sequence > ?'
        params = [after]
        if threat:
            condition += ' AND threat = ?'
            params.append(threat)
        params.append(limit)
        order = 'DESC' if newest else 'ASC'
        rows = self.connection.execute(f'SELECT sequence, body FROM alerts WHERE {condition} ORDER BY sequence {order} LIMIT ?', params).fetchall()
        return [json.loads(body) | {'sequence': seq} for seq, body in rows]

    def summary(self):
        return dict(self.connection.execute('SELECT threat, COUNT(*) FROM alerts GROUP BY threat').fetchall())

    def close(self):
        self.connection.close()

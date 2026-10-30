"""Alert store durability settings and persistence across reopen (WAL + synchronous NORMAL)."""
from persistence.store import AlertStore
from schemas.alert import AlertEvent
from schemas.enums import DetectorType, Severity, ThreatClass


def alert(index):
    return AlertEvent.create(f'flow-{index}', ThreatClass.DDOS, .9, Severity.CRITICAL, 'evidence', '10.0.0.1', '10.0.0.2', 6,
                             timestamp=1_700_000_000_000.0 + index, detection_source=DetectorType.RULE)


def test_wal_with_normal_sync_and_committed_alerts_survive_reopen(tmp_path):
    path = tmp_path / 'alerts.sqlite3'
    store = AlertStore(path)
    assert store.connection.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'wal'
    assert store.connection.execute('PRAGMA synchronous').fetchone()[0] == 1  # NORMAL
    saved = [store.append(alert(i)) for i in range(25)]
    store.close()  # Simulates an application restart: committed alerts must all be there, in order.
    reopened = AlertStore(path)
    assert [a['sequence'] for a in reopened.list()] == list(range(1, 26))
    assert reopened.list()[0]['alert_id'] == saved[0]['alert_id']
    assert reopened.summary() == {'DDOS': 25}
    reopened.close()


def test_a_failed_batch_still_rolls_back_atomically(tmp_path):
    store = AlertStore(tmp_path / 'a.sqlite3')
    first = alert(0)
    store.append(first)
    duplicate = alert(1)
    duplicate.alert_id = first.alert_id  # Violates the UNIQUE alert_id: the whole batch must roll back.
    try:
        store.append_many([alert(2), duplicate])
    except Exception:
        pass
    assert [a['flow_id'] for a in store.list()] == ['flow-0']
    store.close()

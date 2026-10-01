# SQLite alert history and restart validation

Run `python -m pytest tests/test_sqlite_restart.py -q`. Every test sets an
isolated temporary `ALERT_DB`; the existing analyst database is never opened,
deleted or migrated by this validation.

| Behavior | Verified result |
|---|---|
| Empty database | Alerts and threat summary are empty; no invented records |
| Alert persistence | API-generated alert records match SQLite after application shutdown/reopen |
| Application restart | Fresh lifespan and separate API process return original records unchanged |
| Ordering and sequence | Ascending sequence 1–4 before lifespan restart; next alert receives sequence 5; a separate process restart continues 1–3 with sequence 4 |
| Pagination | `after`/`limit` pages reconstruct exact ordered history; `newest` returns descending latest rows; invalid bounds return 422 |
| Threat filtering | DDOS/DGA partitions match saved rows; unknown and SQL-like filter text return no rows |
| Duplicate alert ID | SQLite UNIQUE constraint rejects the second insert; original record remains; subsequent append and reopen work |
| Corrupt or unavailable DB | Store/application startup fails explicitly; corrupt bytes are preserved; no silent fallback DB is created |

**Result: pass.** The store uses the existing SQLite `AUTOINCREMENT` sequence,
unique `alert_id`, committed writes and WAL mode. Duplicate IDs currently raise
`sqlite3.IntegrityError` at the store boundary; this is a fail-closed result,
not an idempotent replacement. The event API generates IDs server-side, so clients
cannot submit an arbitrary alert ID through the normal event endpoint. Corrupt
or unavailable storage prevents application startup rather than risking an empty
analyst view that looks like valid history.

No database schema, backend runtime code, external storage, or migration was
introduced. This test covers local restart durability and query behavior; it is
not a multi-process write-concurrency or disk-failure recovery study.

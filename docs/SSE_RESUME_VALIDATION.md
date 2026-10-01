# SSE disconnect and resume validation

Run `python -m pytest tests/test_sse_resume.py -q` for the targeted loopback
integration test. It launches an owned API process on 127.0.0.1 with an isolated
temporary SQLite database; it does not use or alter analyst alert history.

The test opens a normal SSE connection, posts and verifies three deterministic
alerts, then closes the stream. While no subscriber exists it posts another **105**
alerts. On reconnect, `Last-Event-ID` resumes after the third alert, with a stale
`after=0` query, and delivers exactly those 105 saved alerts. This crosses the
endpoint's 100-row retrieval boundary. The test compares the complete SSE records
with both the POST responses and `/api/alerts` SQLite history, checks each SSE
`id` against the saved sequence, and requires 108 distinct sequences/alert IDs.

The API is then stopped and started with the same SQLite file. History remains
identical. A new connection with `Last-Event-ID` equal to the last saved sequence
receives only the next live alert. A second connection using the explicit `after`
cursor, without the header, also receives only the next alert. The final history
contains exactly 110 distinct alerts. This confirms that SQLite is the replay
source; no in-memory subscriber queue or new broker is required.

**Result (1 October 2026): pass.** The targeted test passed twice. No backend
runtime change was needed: `/api/stream` already advances its cursor from
persisted `sequence`, applies the greater of `after` and `Last-Event-ID`, and
queries SQLite until all pages have been sent. The Monitor hook also checks
`sequence` before adding a visible alert, but this test exercises the direct API
and SSE transport rather than browser rendering. Client network failure during
an individual SSE frame and concurrent subscriber load are outside this test.

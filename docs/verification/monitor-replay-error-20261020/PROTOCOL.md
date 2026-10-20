# Monitor replay-error integration

20 October 2026 IST, baseline `843bd4a`. No product code change planned.
Use an owned production Next.js/FastAPI proxy and disposable SQLite only.
Test server wraps the real replay source: marker-controlled one-event failure
then normal replay after the marker is consumed. No mock API or production switch.

At desktop 1440x1000, tablet 768x1024 and mobile 390x844: show initial saved alert;
start BENIGN replay; first fixture event commits a real alert, then an internal
private-sentinel exception occurs. Monitor must show the safe failure wording,
not private text; failed status must permit retry. Real alert rows remain visible.
Restart BENIGN, complete all 32 events without clearing prior alert history;
failure text disappears, stream remains connected, no page horizontal overflow.
Check browser console and complete API/SQLite records. No detection accuracy claim.

Save rendered state/screenshots, API state and logs. Restore ordinary production
proxy build, stop only owned processes, reset viewport and close temporary tab.
Verify 130 current protected pins (including newly refreshed demo provenance).
Freeze scoped DoD and commit; do not refactor passed UI without a reproduced defect.

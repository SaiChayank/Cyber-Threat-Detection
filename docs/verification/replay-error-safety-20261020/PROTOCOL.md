# Replay error disclosure correction

Baseline `47885f4`, 20 October 2026 IST. Scope: existing replay runtime/cleanup
and uploaded-header error reporting only. No detector, model, parser format,
dataset, accepted gate or alert contract change. Use disposable SQLite and
synthetic fixtures. Preserve original analyst history and all protected artifacts.

Finding to reproduce before correction: raw exception strings are copied into
telemetry (and Monitor) by replay processing/cleanup and returned by upload header
errors. OSError filenames and arbitrary internal exception details must stay in
backend logs. Preserve existing fixed PCAP validation diagnostics.

Acceptance: runtime, iterator, persistence, missing-source, cleanup and header-read
faults never expose a controlled private sentinel in API telemetry/response;
backend logs retain the diagnostic; committed alerts survive; replay can restart
after recovery; expected malformed-PCAP diagnostics remain useful. Check cleanup
after normal completion, processing failure and cancellation before task entry.
No production fault-injection switch or new dependency. Smallest relevant tests
first, then full backend, TypeScript/build, unchanged nine-scenario trace and
100-alert delivery regression because shared API behavior changes. Freeze passing
behavior/results and commit before moving to the next independent package.

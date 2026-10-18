# Monitor integration check for the new upload storage response

19 October 2026 IST; baseline `5261596`. Verify existing UI behavior against real
FastAPI handlers and SQLite in isolated test processes. Do not add a product test
mode, mock API route, frontend framework, dependency or new detection feature.

Use an ephemeral server entry point that injects ENOSPC only on its first capture
temporary-file allocation; subsequent allocation uses the real filesystem in an
owned staging directory. This is controlled fault injection like the unit tests,
not a genuine physical full-disk experiment. The application's request/response,
parser, pipeline and persistence handlers remain real and unmodified.

Loopback API 18519, web 13519; refuse occupied ports and preserve original .env,
analyst DB/WAL/SHM, models and frozen contracts. Build existing frontend with the
documented API proxy environment override, start owned test API and production web
launcher. Use generated one-packet classic-PCAP and invalid-magic .pcap test files
only; no public/raw/evaluation data. No active packets/probes or outgoing messages.

Browser checks: empty/connected state; first valid upload displays generic storage
503 detail without internal path and releases busy controls; retrying the same
file succeeds/one processed event, zero alerts; malformed-file error appears and
valid upload can recover. Check notification/controls at desktop 1440x1000,
tablet 768x1024 and mobile 390x844, no page horizontal overflow. Record console
errors, actual API status trace and staging cleanup. Reset viewport and stop only
owned processes/tabs. No score/accuracy/performance claim.

DoD: real error flows to UI and subsequent work is usable at all three viewports,
zero lost history/unexpected alerts, original protected files unchanged. If a real
UI defect is found, stop and make only the necessary tested correction. A pass
freezes the existing behavior; do not redesign/refactor it for cosmetic reasons.

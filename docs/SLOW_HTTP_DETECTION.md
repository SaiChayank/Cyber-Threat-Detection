# Slow-HTTP exhaustion detection (P0-3)

29 October 2026. Passive TCP metadata only: no probing, no request contents.

Slow-HTTP denial of service (Slowloris, slow POST) ties up a web server by
holding many connections open and trickling a few bytes at long intervals.
The traffic volume is tiny, so the rate and SYN rules cannot see it.

## Features (`features/slow_http.py`)

Per client → server/service pair (the lower port is the service), the state
tracks connections that have carried client data (IP length ≥ 61 bytes, so bare
handshakes and ACKs create no state):

| Feature | Meaning |
| --- | --- |
| `slow_http_open_connections` | Data-carrying connections currently open |
| `slow_http_connections` | Of those, open ≥30 s with mean client rate ≤100 B/s |
| `slow_http_mean_age_s` | Mean open time |
| `slow_http_mean_client_rate_bps` | Mean client bytes per second over each connection's life |
| `slow_http_target` | `server:port` |

A connection closes on an observed TCP FIN or RST from either side (new
optional `TrafficEvent.tcp_fin_rst`, set from PCAP flags and omitted when
absent) or after 120 s without traffic. State is bounded (4,096 pairs, 1,024
open connections each) and staged with the existing failure-safe recovery.

## Rule

A TCP event raises `DDOS` (severity CRITICAL, heuristic strength) with
`ddos_subtype=slow_http` when its pair has **≥50** slow connections. Browsers
keep about six connections per host. Evidence lists the five features above;
the narrative states that request contents were not inspected. The dashboard
shows it as a DDoS alert; its description now mentions slow connections.

Thresholds are development defaults; tune them in P0-5 with the
[lab evaluation harness](LAB_EVALUATION.md).

## Limits

- Flow summaries without client ports cannot be tracked per connection.
- Request completeness is not inspected, so long-polling clients, proxies
  or connection pools that keep 50+ quiet connections to one service can
  match; label them as benign look-alikes in lab captures.
- Slow-read attacks are covered separately (below), not by this rule.
- Without FIN/RST visibility, closed connections linger until the idle timeout.

All nine demo traces are unchanged; runtime pins were re-frozen with
`scripts/refreeze_runtime_pins.py`. Core benchmark after this change:
3,322 metadata events/s, processing + SQLite p95 1.08 ms, same 1,170 alerts.

## Slow-read variant (`features/slow_read.py`)

A slow-read client requests a large response, then advertises a tiny TCP receive
window so the server keeps the connection open while it drains the reply. The
client's advertised window is read from the TCP header (new optional
`TrafficEvent.tcp_window`, from PCAP packets and sFlow headers, omitted when
absent). Per client/service pair the state tracks connections whose non-SYN
client packets advertise a window of 256 bytes or less; a larger advertised
window, a FIN/RST or 120 s idle closes the connection. A TCP event raises
`DDOS` (CRITICAL) with `ddos_subtype=slow_read` when one pair has **50 or
more** such connections held for at least 30 s, unless the trickle rule above
already fired. Evidence: `slow_read_connections`, `slow_read_open_connections`,
`slow_read_mean_age_s`, `slow_read_mean_window`, `slow_read_target`.

Limits: the window field is unscaled, so a legitimate window-scaled receiver
can look small; NetFlow/IPFIX carry no window, so only packet captures and
sFlow samples work; thresholds are development defaults pending lab tuning.
Tests: `tests/test_slow_read.py`.

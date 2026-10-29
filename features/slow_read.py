"""Slow-read exhaustion features from the client's advertised TCP window. Passive.

In a slow-read attack the client requests a large response, then advertises a
tiny receive window so the server must hold the connection open while it drains
the reply a few bytes at a time. Per client/service pair this tracks connections
whose client packets keep advertising a window at or below SMALL_WINDOW. SYN
packets are ignored (the handshake window is unscaled and unrepresentative).
Connections close on an observed FIN/RST or after an idle timeout.
"""
from copy import copy

from features.cow_map import CowMap
from features.slow_http import IDLE_EXPIRY_MS, MAX_ACTIVE, MAX_PAIRS, MIN_AGE_S, orient

SMALL_WINDOW = 256
MIN_SLOW_READ_CONNECTIONS = 50
EVIDENCE = ['slow_read_connections', 'slow_read_open_connections', 'slow_read_mean_age_s',
            'slow_read_mean_window', 'slow_read_target']


class SlowReadState:
    def __init__(self):
        self.pairs = CowMap(MAX_PAIRS)  # (client, server, service) -> {client port: (first, last, window)}

    def fork(self, event):
        staged = copy(self)
        staged.pairs = self.pairs.fork()
        return staged

    def update(self, event):
        oriented = orient(event)
        if oriented is None:
            return empty()
        client, server, service, client_port, from_client = oriented
        key = (client, server, service)
        rows = self.pairs.get(key)
        closing = bool(event.tcp_fin_rst)
        small = (from_client and not event.syn and event.tcp_window is not None
                 and event.tcp_window <= SMALL_WINDOW and not closing)
        if rows is None and not small:
            return empty(f'{server}:{service}')
        rows = dict(rows) if rows else {}  # Replaced on write, never mutated in place.
        now = event.timestamp
        for port in [p for p, row in rows.items() if now - row[1] > IDLE_EXPIRY_MS]:
            del rows[port]
        if closing:
            rows.pop(client_port, None)
        elif small:
            first = rows[client_port][0] if client_port in rows else now
            rows[client_port] = (first, now, event.tcp_window)
            while len(rows) > MAX_ACTIVE:
                del rows[next(iter(rows))]
        elif from_client and not event.syn and event.tcp_window is not None:
            rows.pop(client_port, None)  # The client reopened its window: not a stalled reader.
        if rows:
            self.pairs.set(key, rows)
        else:
            self.pairs.delete(key)
        ages = [(now - row[0]) / 1000 for row in rows.values()]
        slow = sum(age >= MIN_AGE_S for age in ages)
        return dict(slow_read_connections=slow, slow_read_open_connections=len(rows),
                    slow_read_mean_age_s=sum(ages) / len(ages) if ages else 0.0,
                    slow_read_mean_window=sum(row[2] for row in rows.values()) / len(rows) if rows else 0.0,
                    slow_read_target=f'{server}:{service}')


def empty(target=None):
    return dict(slow_read_connections=0, slow_read_open_connections=0, slow_read_mean_age_s=0.0,
                slow_read_mean_window=0.0, slow_read_target=target)

"""Causal, bounded slow-HTTP exhaustion features from passive TCP metadata.

Slow-HTTP denial of service (for example Slowloris) holds many connections to a
web service open by trickling a few bytes at long intervals. Per client/service
pair this tracks connections that have carried client data, their age and mean
client byte rate. Connections close on an observed FIN/RST or after an idle
timeout. Request contents are never inspected.
"""
from collections import OrderedDict
from copy import copy

from features.cow_map import CowMap

IDLE_EXPIRY_MS = 120000
DATA_MIN_BYTES = 61  # IP total length above bare TCP/IP headers and common options.
MAX_PAIRS = 4096
MAX_ACTIVE = 1024
MIN_AGE_S = 30
MAX_CLIENT_RATE_BPS = 100
MIN_SLOW_CONNECTIONS = 50  # Browsers keep about six connections per host.
EVIDENCE = ['slow_http_connections', 'slow_http_open_connections', 'slow_http_mean_age_s',
            'slow_http_mean_client_rate_bps', 'slow_http_target']


def orient(event):
    """(client, server, service port, client port, from_client) for a TCP event, or None."""
    if event.protocol != 6 or not event.src_port or not event.dst_port or event.src_port == event.dst_port:
        return None
    if event.dst_port < event.src_port:
        return str(event.src_ip), str(event.dst_ip), event.dst_port, event.src_port, True
    return str(event.dst_ip), str(event.src_ip), event.src_port, event.dst_port, False


class Pair:
    __slots__ = ('active',)

    def __init__(self):
        self.active = OrderedDict()  # client port -> (first_ms, last_ms, client_bytes)

    def copy(self):
        staged = copy(self)
        staged.active = self.active.copy()  # Rows are immutable tuples.
        return staged


class SlowHttpState:
    def __init__(self):
        self.pairs = CowMap(MAX_PAIRS)  # (client, server, service port) -> Pair, replaced on write

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
        pair = self.pairs.get(key)
        if pair is None and not (from_client and event.bytes >= DATA_MIN_BYTES):
            return empty(f'{server}:{service}')
        pair = pair.copy() if pair else Pair()
        now = event.timestamp
        for port in [p for p, row in pair.active.items() if now - row[1] > IDLE_EXPIRY_MS]:
            del pair.active[port]
        if event.tcp_fin_rst:
            pair.active.pop(client_port, None)
        elif from_client and event.bytes >= DATA_MIN_BYTES:
            first, _, sent = pair.active.pop(client_port, None) or (now, now, 0)
            pair.active[client_port] = (first, now, sent + event.bytes)
            if len(pair.active) > MAX_ACTIVE:
                pair.active.popitem(last=False)
        if pair.active:
            self.pairs.set(key, pair)
        else:
            self.pairs.delete(key)
        ages = [(now - row[0]) / 1000 for row in pair.active.values()]
        rates = [row[2] / max(age, 1.0) for row, age in zip(pair.active.values(), ages)]
        slow = sum(age >= MIN_AGE_S and rate <= MAX_CLIENT_RATE_BPS for age, rate in zip(ages, rates))
        return dict(slow_http_connections=slow, slow_http_open_connections=len(pair.active),
                    slow_http_mean_age_s=sum(ages) / len(ages) if ages else 0.0,
                    slow_http_mean_client_rate_bps=sum(rates) / len(rates) if rates else 0.0,
                    slow_http_target=f'{server}:{service}')


def empty(target=None):
    return dict(slow_http_connections=0, slow_http_open_connections=0, slow_http_mean_age_s=0.0,
                slow_http_mean_client_rate_bps=0.0, slow_http_target=target)

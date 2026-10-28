"""Causal, bounded encrypted-session metadata features. No payload decryption.

A session is one client/server/service tuple; it restarts after 60 seconds idle.
Features cover handshake fingerprints seen in the session (client JA3/JA4,
server JA3S), packet-size and timing regularity, and fingerprint rarity: how
many distinct clients have offered the same client fingerprint so far.
"""
import math
from collections import OrderedDict, deque
from copy import copy

IDLE_MS = 60000
MAX_SESSIONS = 4096
MAX_FINGERPRINTS = 4096
MAX_CLIENTS_PER_FINGERPRINT = 64
MAX_CLIENTS = 4096
SEQUENCE = 64
SMALL_PACKET_BYTES = 200


def _cv(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) / max(mean, 1e-9)


def session_key(event):
    """Orient both directions to (client, server, service port); the lower port serves."""
    if event.tls_server_fingerprint or (event.src_port and event.src_port < event.dst_port):
        return str(event.dst_ip), str(event.src_ip), event.src_port
    return str(event.src_ip), str(event.dst_ip), event.dst_port


class Session:
    __slots__ = ('first', 'last', 'packets', 'sizes', 'times', 'ja3', 'ja3s', 'ja4')

    def __init__(self, timestamp):
        self.first = self.last = timestamp
        self.packets = 0
        self.sizes, self.times = deque(maxlen=SEQUENCE), deque(maxlen=SEQUENCE)
        self.ja3 = self.ja3s = self.ja4 = None

    def copy(self):
        staged = copy(self)
        staged.sizes, staged.times = self.sizes.copy(), self.times.copy()
        return staged


class TlsSessionState:
    def __init__(self):
        self.sessions = OrderedDict()
        self.fingerprint_clients = OrderedDict()  # client fingerprint -> frozenset of clients
        self.clients = OrderedDict()  # TLS clients with an observed client fingerprint

    def fork(self, event):
        """Copy only the state this event can change; other entries are never mutated."""
        staged = copy(self)
        if not event.encrypted:
            return staged
        key = session_key(event)
        staged.sessions = self.sessions.copy()
        if key in staged.sessions:
            staged.sessions[key] = staged.sessions[key].copy()
        staged.fingerprint_clients = self.fingerprint_clients.copy()
        staged.clients = self.clients.copy()
        return staged

    def update(self, event):
        if not event.encrypted:
            return empty()
        key = session_key(event)
        session = self.sessions.pop(key, None)
        if session is None or event.timestamp - session.last > IDLE_MS:
            session = Session(event.timestamp)
        self.sessions[key] = session
        if len(self.sessions) > MAX_SESSIONS:
            self.sessions.popitem(last=False)
        session.last = event.timestamp
        session.packets += event.packets
        session.sizes.append(event.bytes / event.packets)
        session.times.append(event.timestamp)
        session.ja3 = event.tls_fingerprint or session.ja3
        session.ja4 = event.tls_ja4 or session.ja4
        session.ja3s = event.tls_server_fingerprint or session.ja3s
        fingerprint = event.tls_ja4 or event.tls_fingerprint
        if fingerprint:
            client = key[0]
            self.clients.pop(client, None)
            self.clients[client] = True
            if len(self.clients) > MAX_CLIENTS:
                self.clients.popitem(last=False)
            members = self.fingerprint_clients.pop(fingerprint, frozenset())
            if client not in members and len(members) < MAX_CLIENTS_PER_FINGERPRINT:
                members = members | {client}
            self.fingerprint_clients[fingerprint] = members
            if len(self.fingerprint_clients) > MAX_FINGERPRINTS:
                self.fingerprint_clients.popitem(last=False)
        session_fingerprint = session.ja4 or session.ja3
        intervals = [(b - a) / 1000 for a, b in zip(session.times, list(session.times)[1:])]
        return dict(
            tls_ja3=session.ja3, tls_ja3s=session.ja3s, tls_ja4=session.ja4,
            tls_session_packets=session.packets,
            tls_session_duration_s=(session.last - session.first) / 1000,
            tls_session_mean_bytes=sum(session.sizes) / len(session.sizes),
            tls_session_size_cv=_cv(list(session.sizes)),
            tls_session_small_fraction=sum(s < SMALL_PACKET_BYTES for s in session.sizes) / len(session.sizes),
            tls_session_iat_mean_s=sum(intervals) / len(intervals) if intervals else 0.0,
            tls_session_iat_cv=_cv(intervals),
            tls_fingerprint_clients=len(self.fingerprint_clients.get(session_fingerprint, ())) if session_fingerprint else 0,
            tls_client_population=len(self.clients))


def empty():
    return dict(tls_ja3=None, tls_ja3s=None, tls_ja4=None, tls_session_packets=0,
                tls_session_duration_s=0.0, tls_session_mean_bytes=0.0, tls_session_size_cv=0.0,
                tls_session_small_fraction=0.0, tls_session_iat_mean_s=0.0, tls_session_iat_cv=0.0,
                tls_fingerprint_clients=0, tls_client_population=0)

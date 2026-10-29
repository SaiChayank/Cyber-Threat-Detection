"""Receive-only live collector for NetFlow v5/v9, IPFIX and sFlow v5 export datagrams.

Exporters push datagrams to a collector port; this collector only listens. It never
calls send/sendto/connect, never answers an exporter and never contacts any host, so
the ingest path stays one-directional. Datagrams are decoded by the same
FlowExportDecoder used for capture files. Defaults are conservative: loopback bind,
optional exporter allowlist (datagrams from other sources are dropped and counted),
datagrams capped at 64 KiB, and no analyst history written.
"""
import ipaddress
import socket
import time

from ingest.flow_export import FlowExportDecoder

MAX_DATAGRAM = 65535


class FlowCollector:
    def __init__(self, bind='127.0.0.1', port=2055, allow=None, decoder=None):
        address = ipaddress.ip_address(bind)
        self.allow = {str(ipaddress.ip_address(a)) for a in allow} if allow else None
        self.decoder = decoder or FlowExportDecoder()
        self.stats = dict(received=0, dropped_not_allowed=0, dropped_oversize=0)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self.socket.bind((str(address), port))
        except OSError:
            self.socket.close()
            raise
        self.socket.settimeout(0.25)
        self.address = self.socket.getsockname()

    def close(self):
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def events(self, max_datagrams=None, idle_timeout=None, stop=None):
        """Yield TrafficEvents as datagrams arrive; stop on a limit, idleness or stop()."""
        seen, last = 0, time.monotonic()
        while max_datagrams is None or seen < max_datagrams:
            if stop is not None and stop():
                return
            try:
                payload, (exporter, *_) = self.socket.recvfrom(MAX_DATAGRAM + 1)
            except socket.timeout:
                if idle_timeout is not None and time.monotonic() - last > idle_timeout:
                    return
                continue
            last = time.monotonic()
            self.stats['received'] += 1
            if len(payload) > MAX_DATAGRAM:
                self.stats['dropped_oversize'] += 1
                continue
            if self.allow is not None and exporter.split('%')[0] not in self.allow:
                self.stats['dropped_not_allowed'] += 1
                continue
            seen += 1
            yield from self.decoder.decode(payload, exporter.split('%')[0], time.time() * 1000)

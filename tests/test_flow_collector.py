"""Live flow-export collector: receive-only, bounded, loopback by default."""
import json
import socket
import threading

import pytest

from ingest.flow_collector import MAX_DATAGRAM, FlowCollector
from replay import collector as cli
from tests.test_flow_export import netflow5, v5_record


def exporter(port, datagrams, bind='127.0.0.1'):
    """Test-side exporter pushing datagrams at the collector."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, 0))
        for datagram in datagrams:
            sock.sendto(datagram, ('127.0.0.1', port))


def flows(count=3):
    return netflow5([v5_record('10.0.0.1', '192.0.2.10', 51000 + i, 80, 6, 5, 400, 0x18, 400_000 + i)
                     for i in range(count)])


def test_collector_decodes_pushed_datagrams_and_stops_at_the_limit():
    with FlowCollector(port=0) as collector:
        port = collector.address[1]
        sender = threading.Thread(target=exporter, args=(port, [flows(3), flows(2)]))
        sender.start()
        events = list(collector.events(max_datagrams=2, idle_timeout=5))
        sender.join()
    assert len(events) == 5 and collector.stats['received'] == 2
    assert {str(e.dst_ip) for e in events} == {'192.0.2.10'}


class ReceiveOnly:
    """Proxy for the collector's socket: any outbound call fails the test."""

    FORBIDDEN = frozenset({'send', 'sendto', 'sendall', 'sendmsg', 'connect', 'connect_ex'})

    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.calls = []

    def __getattr__(self, name):
        if name in self.FORBIDDEN:
            pytest.fail(f'The collector must be receive-only; it called socket.{name}')
        self.calls.append(name)
        return getattr(self.wrapped, name)


def test_collector_never_sends_connects_or_replies():
    with FlowCollector(port=0) as collector:
        port = collector.address[1]
        collector.socket = guard = ReceiveOnly(collector.socket)
        sender = threading.Thread(target=exporter, args=(port, [flows(), b'junk', flows(1)]))
        sender.start()
        events = list(collector.events(max_datagrams=3, idle_timeout=5))
        sender.join()
    assert len(events) == 4
    assert 'recvfrom' in guard.calls and not set(guard.calls) & ReceiveOnly.FORBIDDEN


def test_source_code_contains_no_outbound_socket_calls():
    from pathlib import Path
    for path in ('ingest/flow_collector.py', 'replay/collector.py'):
        text = (Path(__file__).resolve().parents[1] / path).read_text(encoding='utf-8')
        for call in ('.send(', '.sendto(', '.sendall(', '.connect(', 'create_connection', 'urlopen', 'requests.'):
            assert call not in text, (path, call)


def test_allowlist_drops_unlisted_exporters():
    with FlowCollector(port=0, allow=['192.0.2.99']) as collector:
        port = collector.address[1]
        sender = threading.Thread(target=exporter, args=(port, [flows()]))
        sender.start()
        events = list(collector.events(idle_timeout=1.0))
        sender.join()
    assert events == [] and collector.stats['dropped_not_allowed'] == 1


def test_malformed_datagrams_are_counted_not_raised():
    with FlowCollector(port=0) as collector:
        port = collector.address[1]
        sender = threading.Thread(target=exporter, args=(port, [b'\x00' * 7, b'garbage datagram', flows(1)]))
        sender.start()
        events = list(collector.events(max_datagrams=3, idle_timeout=5))
        sender.join()
    assert len(events) == 1
    assert collector.decoder.stats['malformed'] + collector.decoder.stats['unsupported'] == 2


def test_stop_callback_ends_the_loop():
    with FlowCollector(port=0) as collector:
        assert list(collector.events(stop=lambda: True)) == []


def test_bad_arguments_are_rejected():
    with pytest.raises(ValueError):
        FlowCollector(bind='not-an-address')
    with pytest.raises(ValueError):
        FlowCollector(allow=['nope'])
    assert MAX_DATAGRAM == 65535


def test_cli_prints_alerts_and_stats_and_rejects_bad_port(capsys):
    records = [v5_record(f'10.1.{i // 250}.{i % 250 + 1}', '192.0.2.10', 50000 + i, 80, 6, 400, 16000, 0x02, 400_000 + i * 20)
               for i in range(25)]
    free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    free.bind(('127.0.0.1', 0))
    port = free.getsockname()[1]
    free.close()
    sender = threading.Timer(0.6, exporter, args=(port, [netflow5(records)]))
    sender.start()
    assert cli.main(['--port', str(port), '--max-datagrams', '1', '--idle-timeout', '10']) == 0
    sender.join()
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith('listening (receive-only) on 127.0.0.1')
    alerts = [json.loads(line) for line in lines[1:-1]]
    assert any(a['threat_class'] == 'DDOS' for a in alerts)
    assert json.loads(lines[-1])['collector']['received'] == 1
    with pytest.raises(SystemExit):
        cli.main(['--port', '70000'])

import pytest
from benchmarks.pcap_throughput import main, run, write_capture
from ingest.pcap_reader import PcapReader


def test_report_has_positive_fields(tmp_path):
    report = run(1000, tmp_path / 'report.json')
    for key in ('packets_per_second', 'flows_per_second', 'sustained_mbps', 'elapsed_seconds',
                'capture_bytes', 'capture_duration_seconds', 'realtime_factor',
                'parse_only_packets_per_second', 'parse_only_sustained_mbps'):
        assert report[key] > 0, key
    for key in ('generated_at_utc', 'python', 'platform', 'hardware', 'workload', 'scope', 'capture_sha256'):
        assert report[key], key
    assert report['packets'] == 1000
    assert (tmp_path / 'report.json').exists()


def test_capture_parses_back_to_requested_count(tmp_path):
    path = tmp_path / 'capture.pcap'
    write_capture(path, 1000)
    count = sum(len(batch) for batch in PcapReader().read_packets(path))
    assert count == 1000


def test_generation_is_deterministic(tmp_path):
    first, second = tmp_path / 'a.pcap', tmp_path / 'b.pcap'
    write_capture(first, 1000)
    write_capture(second, 1000)
    assert first.read_bytes() == second.read_bytes()


def test_rejects_small_packet_count(tmp_path):
    with pytest.raises(SystemExit):
        main(['--packets', '999', '--output', str(tmp_path / 'r.json')])


def test_benign_workload_raises_no_flood_or_recon_alerts(tmp_path):
    report = run(1000, tmp_path / 'report.json')
    assert not {'DDOS', 'RECONNAISSANCE'} & set(report['alerts_by_class'])

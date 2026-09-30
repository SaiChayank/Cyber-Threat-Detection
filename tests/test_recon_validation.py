"""Integrity checks for labelled, causal reconnaissance replays."""
from datasets.validate_recon import events, reference, score
from detection.pipeline import Pipeline


def test_vertical_horizontal_and_mixed_fanout_shapes():
    vertical = list(events('vertical', 100))
    horizontal = list(events('horizontal', 100))
    mixed = list(events('mixed', 100))
    assert reference(vertical, vertical[-1])['destination_count'] == 1
    assert reference(vertical, vertical[-1])['port_count'] == 32
    assert reference(horizontal, horizontal[-1])['destination_count'] == 32
    assert reference(horizontal, horizontal[-1])['port_count'] == 1
    assert reference(mixed, mixed[-1])['destination_count'] == 16
    assert reference(mixed, mixed[-1])['port_count'] == 32
    assert all(event.syn and event.syn_packets == 1 for event in vertical + horizontal + mixed)


def test_slow_scan_reference_never_uses_future_events():
    slow = list(events('horizontal', 2000))
    assert reference(slow[:6], slow[5])['destination_count'] == 6
    assert reference(slow[:7], slow[6])['destination_count'] == 6
    assert reference(slow, slow[-1])['destination_count'] == 6
    assert reference(slow, slow[-1])['observed_event_rate'] == .6


def test_authorised_scanner_has_identical_visible_stream_to_vertical_scan():
    attack = score('vertical_scan', True, 'vertical', 100)
    authorised = score('authorised_vulnerability_scanner', False, 'vertical', 100)
    assert attack['observed_stream_sha256'] == authorised['observed_stream_sha256']
    assert attack['first_alert']['independent_reference'] == authorised['first_alert']['independent_reference']
    assert attack['verdict'] == 'TP'
    assert authorised['verdict'] == 'FP'


def test_horizontal_scan_emits_one_alert_per_source_not_per_target():
    pipeline = Pipeline()
    alerts = [alert for event in events('horizontal', 100)
              for alert in pipeline.process(event)
              if alert.threat_class == 'RECONNAISSANCE']
    assert len(alerts) == 1
    assert alerts[0].raw_evidence_metrics['destination_count'] == 10

    second_source = [event.model_copy(update={
        'src_ip': '10.0.0.11', 'timestamp': event.timestamp + 10_000})
        for event in events('horizontal', 100)]
    alerts = [alert for event in second_source for alert in pipeline.process(event)
              if alert.threat_class == 'RECONNAISSANCE']
    assert len(alerts) == 1
    assert alerts[0].src_ip == '10.0.0.11'

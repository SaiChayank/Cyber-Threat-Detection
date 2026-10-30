"""Slow periodic beaconing: contacts too far apart for the 60 s history, measured on real Neris traffic."""
import random

import pytest

from detection import rule_thresholds
from detection.pipeline import Pipeline
from features.beacon_tracker import BeaconTracker
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def contact(t_ms, dst='203.0.113.9', port=6251, src='10.0.0.5', protocol=6, packets_of_connection=1):
    return [TrafficEvent(timestamp=t_ms + i * 40, src_ip=src, dst_ip=dst, src_port=50000 + (t_ms // 1000) % 1000,
                         dst_port=port, protocol=protocol, bytes=120)
            for i in range(packets_of_connection)]


def series(gaps_s, **kw):
    t, events = START, []
    for gap in [0] + list(gaps_s):
        t += gap * 1000
        events += contact(t, **kw)
    return events


def slow_alerts(events, pipeline=None):
    pipeline = pipeline or Pipeline()
    return [a for e in events for a in pipeline.process(e)
            if a.threat_class == 'BOTNET_C2' and a.raw_evidence_metrics.get('c2_basis') == 'slow_periodic_contact']


def test_sixty_second_beacon_alerts_once_after_ten_contacts_and_stays_quiet_for_an_hour():
    events = series([60.0] * 40)  # 41 contacts over 40 minutes: far beyond the 60 s history
    alerts = slow_alerts(events)
    assert len(alerts) == 1
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['slow_beacon_events'] == 10 and abs(evidence['slow_beacon_mean_s'] - 60) < .1
    assert evidence['slow_beacon_cv'] < .01 and evidence['slow_beacon_peer'] == '203.0.113.9:6251'
    assert alerts[0].severity == 'HIGH' and 'content not inspected' in alerts[0].supporting_evidence
    # A new alert after the one-hour de-duplication window expires.
    assert len(slow_alerts(series([60.0] * 99))) == 2  # Alerts at about minute 9 and minute 69.


def test_irregular_or_too_few_contacts_do_not_alert():
    rng = random.Random(3)
    assert slow_alerts(series([rng.uniform(20, 120) for _ in range(40)])) == []   # Variation far above .1.
    assert slow_alerts(series([60.0] * 8)) == []                                  # Only 9 contacts.
    assert slow_alerts(series([4.0] * 40)) == []                                  # Faster than the slow range.


def test_packets_of_one_connection_count_as_one_contact():
    # 12 contacts a minute apart, 25 packets each: the series must still be 12 contacts, not 300.
    assert len(slow_alerts(series([60.0] * 11, ), Pipeline())) == 1
    tracker = BeaconTracker()
    last = None
    for event in series([60.0] * 11, ) and [e for t in range(12) for e in contact(START + t * 60000, packets_of_connection=25)]:
        last = tracker.update(event)
    assert last['slow_beacon_events'] == 12


@pytest.mark.parametrize('kw', [dict(port=123), dict(port=53, protocol=17), dict(port=138, dst='192.168.20.255'),
                                dict(port=5353, dst='224.0.0.251', protocol=17), dict(port=1947, dst='10.1.2.255'),
                                dict(port=137, dst='255.255.255.255', protocol=17)])
def test_legitimately_periodic_services_and_broadcasts_are_never_slow_beacons(kw):
    assert slow_alerts(series([60.0] * 30, **kw)) == []


def test_a_long_silence_starts_a_new_series():
    gaps = [60.0] * 5 + [3 * 3600.0] + [60.0] * 5  # Only 6 contacts on either side of the gap.
    assert slow_alerts(series(gaps)) == []


def test_state_is_bounded_and_failed_events_leave_no_trace():
    tracker = BeaconTracker()
    for i in range(9000):
        tracker.update(TrafficEvent(timestamp=START + i, src_ip='10.0.0.5', dst_ip=f'198.51.{(i // 250) % 250}.{i % 250 + 1}',
                                    dst_port=443 + i % 3, protocol=6, bytes=100))
    assert len(tracker.series) <= 8192
    pipeline = Pipeline()
    for e in series([60.0] * 8):
        pipeline.process(e)
    before = dict(pipeline.extractor.beacons.series.items())

    def fail(alerts):
        raise OSError('disk full')
    with pytest.raises(OSError):
        pipeline.process(contact(START + 9 * 60000)[0], persist=fail)
    assert dict(pipeline.extractor.beacons.series.items()) == before


def test_thresholds_are_read_at_call_time(monkeypatch):
    events = series([60.0] * 20)
    assert slow_alerts(events)
    monkeypatch.setattr(rule_thresholds, 'SLOW_C2_MIN_MEAN_S', 120)
    assert slow_alerts(events) == []

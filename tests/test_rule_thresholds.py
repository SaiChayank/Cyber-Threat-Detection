"""Named rule thresholds are read at call time and the tuned C2 default is pinned."""
from detection import rule_thresholds
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def beacons(gaps):
    t, events = START, []
    for gap in gaps:
        t += gap
        events.append(TrafficEvent(timestamp=t, src_ip='10.0.0.5', dst_ip='203.0.113.9', src_port=50000, dst_port=8080,
                                   protocol=6, bytes=300))
    return events


def c2_alerts(events):
    pipeline = Pipeline()
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'BOTNET_C2' and a.detection_source in ('RULE', 'HYBRID')]


def test_tuned_default_and_call_time_override(monkeypatch):
    assert rule_thresholds.C2_MAX_IAT_CV == .3
    # Gaps alternate 4 s and 8 s: inter-arrival CV about 0.33 over the window, regular enough only if loosened.
    irregular = beacons([4000, 8000] * 8)
    monkeypatch.setattr(rule_thresholds, 'C2_MAX_IAT_CV', .05)
    assert c2_alerts(irregular) == []
    monkeypatch.setattr(rule_thresholds, 'C2_MAX_IAT_CV', .6)
    assert c2_alerts(irregular)


def test_roughly_regular_beacons_alert_at_the_tuned_default_but_not_at_the_old_one(monkeypatch):
    roughly_regular = beacons([5000, 5600, 4500, 5200, 4700, 5900, 4400, 5300, 5100, 4800, 5500, 4600])
    assert c2_alerts(roughly_regular)  # CV about 0.1 passes the tuned default .3
    monkeypatch.setattr(rule_thresholds, 'C2_MAX_IAT_CV', .05)
    assert c2_alerts(roughly_regular) == []  # The old default missed it.

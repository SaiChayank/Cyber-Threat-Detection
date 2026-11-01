"""Long readable names are not DGA alerts; long consonant-heavy generated strings still are."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def dga(name):
    event = TrafficEvent(timestamp=START, src_ip='10.0.0.5', dst_ip='10.0.0.1', src_port=40000, dst_port=53,
                         protocol=17, packets=1, bytes=80, dns_name=name)
    return [a for a in Pipeline().process(event) if a.threat_class == 'DGA_DOMAINS']


def test_readable_long_compound_is_not_dga():
    # Both alerted before the guard (real benign DNS, CIC benign captures); vowel share 0.42 and 0.43.
    assert dga('diakoniewerk-duisburg.de') == []
    assert dga('youtubethumbnaildownloader.com') == []


def test_generated_consonant_heavy_string_still_alerts():
    assert dga('xkqzvbnmwpltrgfhjcdsbk.com')

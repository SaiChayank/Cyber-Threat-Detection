"""Encrypted-session indicators from handshake metadata alone. No decryption.

Two paths raise ENCRYPTED_MALWARE suspicion:
- indicator: the session's client JA3/JA4 or server JA3S is in the
  operator-maintained list (tls_indicators.json);
- behaviour: a session with a rarely seen client fingerprint that sends small,
  machine-regular packets (beacon-like size and timing), once enough TLS
  clients have been observed for rarity to mean anything.
Thresholds are development defaults to be tuned on labelled lab captures.
"""
import json
from pathlib import Path

INDICATORS = Path(__file__).with_name('tls_indicators.json')
FORMAT = 'ps26145-tls-indicators/1'
KINDS = ('ja3', 'ja3s', 'ja4', 'quic')

MIN_SESSION_PACKETS = 8
MAX_SIZE_CV = .25
MAX_IAT_CV = .25
MAX_MEAN_BYTES = 600
MAX_FINGERPRINT_CLIENTS = 1
MIN_CLIENT_POPULATION = 5


def load(path=INDICATORS):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('format') != FORMAT:
        raise ValueError(f'TLS indicator list must use format {FORMAT!r}')
    return {kind: {key.lower(): str(note) for key, note in data.get(kind, {}).items()} for kind in KINDS}


def indicator_match(features, indicators):
    """Return (kind, fingerprint, note) for the first listed session fingerprint."""
    for kind in KINDS:
        value = features.get(f'tls_{kind}')
        if value and value.lower() in indicators[kind]:
            return kind, value, indicators[kind][value.lower()]
    return None


def behaviour_match(features):
    return (bool(features.get('tls_ja4') or features.get('tls_ja3') or features.get('tls_quic'))
            and features['tls_session_packets'] >= MIN_SESSION_PACKETS
            and features['tls_session_size_cv'] <= MAX_SIZE_CV
            and features['tls_session_iat_cv'] <= MAX_IAT_CV
            and features['tls_session_mean_bytes'] <= MAX_MEAN_BYTES
            and features['tls_client_population'] >= MIN_CLIENT_POPULATION
            and features['tls_fingerprint_clients'] <= MAX_FINGERPRINT_CLIENTS)


EVIDENCE = ['encrypted', 'tls_ja3', 'tls_ja3s', 'tls_ja4', 'tls_quic', 'tls_session_packets',
            'tls_session_duration_s', 'tls_session_mean_bytes', 'tls_session_size_cv',
            'tls_session_small_fraction', 'tls_session_iat_mean_s', 'tls_session_iat_cv',
            'tls_fingerprint_clients', 'tls_client_population']

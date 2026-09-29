"""Deterministic complete-DNS metadata scenarios for development only."""
import random

from schemas.traffic_event import TrafficEvent


# Scenario/configuration split, never a random query-row split. These identifiers
# and labels are evaluation metadata, not detector features.
SCENARIOS = (
    # Configuration/training side.
    ('train_long_a', 'training', True, 'long', 1, 11, 'relay.alpha.test', 450),
    ('train_long_aaaa', 'training', True, 'long', 28, 12, 'relay.beta.test', 700),
    ('train_long_txt', 'training', True, 'long', 16, 13, 'relay.gamma.test', 550),
    ('train_long_null', 'training', True, 'long', 10, 14, 'relay.delta.test', 650),
    ('train_multi_a', 'training', True, 'multi', 1, 15, 'relay.epsilon.test', 800),
    ('train_cdn', 'training', False, 'cdn', 1, 21, 'edge.cloud.test', 450),
    ('train_telemetry', 'training', False, 'telemetry', 1, 22, 'metrics.vendor.test', 900),
    ('train_discovery', 'training', False, 'discovery', 33, 23, 'corp.example', 500),
    ('train_txt', 'training', False, 'txt', 16, 24, 'mail.example', 500),
    ('train_machine', 'training', False, 'machine', 28, 25, 'compute.cloud.test', 600),
    # Validation-only seeds, domain suffixes, rates, and shapes.
    ('val_long_a', 'validation', True, 'long', 1, 101, 'channel.zeta.test', 1800),
    ('val_long_aaaa', 'validation', True, 'long', 28, 102, 'channel.eta.test', 1100),
    ('val_multi_txt', 'validation', True, 'multi', 16, 103, 'channel.theta.test', 1200),
    ('val_multi_null', 'validation', True, 'multi', 10, 104, 'channel.iota.test', 950),
    ('val_long_txt', 'validation', True, 'long', 16, 105, 'channel.kappa.test', 1500),
    ('val_cdn', 'validation', False, 'cdn', 28, 111, 'assets.provider.test', 350),
    ('val_telemetry', 'validation', False, 'telemetry', 16, 112, 'signals.service.test', 700),
    ('val_discovery', 'validation', False, 'discovery', 33, 113, 'local.example', 650),
    ('val_txt', 'validation', False, 'txt', 16, 114, 'email.example', 800),
    ('val_machine', 'validation', False, 'machine', 1, 115, 'instances.cloud.test', 400),
)


def events(spec, count=12):
    _, _, _, pattern, qtype, seed, base, interval_ms = spec
    rng = random.Random(seed)
    alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
    for index in range(count):
        if pattern == 'long':
            labels = [str(index % 10), ''.join(rng.choice(alphabet) for _ in range(58))]
        elif pattern == 'multi':
            labels = [''.join(rng.choice(alphabet) for _ in range(24)) for _ in range(3)]
        elif pattern == 'cdn':
            labels = ['asset-' + ''.join(rng.choice('abcdef0123456789') for _ in range(22))]
        elif pattern == 'telemetry':
            labels = ['client-' + ''.join(rng.choice(alphabet) for _ in range(18))]
        elif pattern == 'discovery':
            labels = [('_ldap', '_kerberos', '_sip')[index % 3], '_tcp']
        elif pattern == 'txt':
            # Repeated legitimate DKIM selector: long TXT label alone is weak.
            labels = ['selector-' + 'a' * 45, '_domainkey']
        elif pattern == 'machine':
            labels = [f'vm-{index:04d}-{seed}', 'region-1']
        else:
            raise ValueError(pattern)
        yield TrafficEvent(timestamp=1_700_000_000_000 + index * interval_ms,
                           src_ip='192.0.2.10', dst_ip='192.0.2.53', src_port=40000 + index,
                           dst_port=53, protocol=17, bytes=90,
                           dns_name='.'.join(labels + [base]), dns_type=qtype)

"""Incremental passive inference. No networking operations."""
import time
from collections import deque, OrderedDict
from features.extractor import FeatureExtractor
from ml.model import Model
from ml.dga import DgaModel, domain_label, FEATURE_VERSION
from detection.dga_rules import conservative_rule
from detection.dns_tunnel_candidate import candidate_reason
from detection import rule_thresholds as thresholds, spoof_indicators, tls_indicators
from features import slow_http as slow_http_features
from features import slow_read as slow_read_features
from features.cow_map import CowMap, shallow
from features.dns_tunnel import FEATURE_NAMES as DNS_TUNNEL_FEATURES
from schemas.alert import AlertEvent
from schemas.enums import ThreatClass, Severity, DetectorType
from schemas.flow_record import FlowRecord

EVIDENCE = {
    'DDOS': ['packet_rate', 'byte_rate', 'source_entropy', 'syn_fraction',
             'source_entropy_partial', 'rate_window_seconds', 'rate_window_resolution_ms'],
    'BOTNET_C2': ['iat_mean', 'iat_cv', 'history_count', 'destination_count'],
    'DGA_DOMAINS': ['domain_entropy', 'domain_length', 'domain_label_length', 'bigram_surprise'],
    'DNS_TUNNELLING': ['domain_length', 'domain_label_length', 'domain_entropy', 'txt_record'],
    'ENCRYPTED_MALWARE': ['encrypted', 'fingerprint_risk', 'size_cv', 'iat_cv'],
    'RECONNAISSANCE': ['destination_count', 'port_count', 'syn_fraction'],
    'DATA_EXFILTRATION': ['egress_bytes', 'observed_byte_ratio', 'reverse_available'],
}


class Pipeline:
    def __init__(self, dns_tunnel_candidate=False):
        self.extractor = FeatureExtractor()
        self.model = Model()
        self.dga_model = DgaModel()
        self.processed = 0
        self.latencies = deque(maxlen=10000)
        self.dedup = {}
        self.sessions = CowMap(4096)
        self.dns_tunnel_candidate = dns_tunnel_candidate
        self.tls_indicators = tls_indicators.load()

    def flow_id(self, event):
        if event.flow_id:
            return event.flow_id
        key = (str(event.src_ip), str(event.dst_ip), event.src_port, event.dst_port, event.protocol)
        previous = self.sessions.get(key)
        start = previous[0] if previous and event.timestamp - previous[1] < 60000 else event.timestamp
        self.sessions.set(key, (start, event.timestamp))
        return FlowRecord.compute_flow_id(*key, start)

    def process(self, event, persist=None):
        """Commit causal/dedup state only after inference and optional persistence.

        The synchronous caller supplies an atomic alert-batch writer. Exceptions
        leave the prior state intact, so the failed observation can be retried.
        Models are immutable during inference; no full model/history copy is made.
        """
        started = time.perf_counter()
        staged = shallow(self)
        staged.extractor = self.extractor.fork(event)
        staged.sessions = self.sessions.fork()
        alerts = staged._detect(event)
        processing_ms = (time.perf_counter() - started) * 1000
        result = persist(alerts) if persist is not None else alerts
        late = staged.extractor.late_events != self.extractor.late_events
        self.extractor = staged.extractor
        self.sessions = staged.sessions
        self.dedup = staged.dedup
        self.processed = staged.processed
        if not late:
            self.latencies.append(processing_ms)  # Preserve inference-only telemetry scope.
        return result

    def _detect(self, event):
        f = self.extractor.update(event)
        self.processed += 1
        if f is None:
            return []
        label, confidence = self.model.predict(f)
        fid = self.flow_id(event)
        hits = {label: (confidence, DetectorType.ML)} if label != 'BENIGN' and confidence >= .8 else {}
        syn_flood = (event.protocol == 6 and f['syn_target_packet_rate'] >= 1000
                     and f['syn_target_fraction'] is not None
                     and f['syn_target_fraction'] >= .70)
        udp_flood = event.protocol == 17 and f['udp_target_packet_rate'] >= 1000
        # Many long-lived, low-rate client connections to one service: slow-HTTP exhaustion.
        slow_http = event.protocol == 6 and f['slow_http_connections'] >= slow_http_features.MIN_SLOW_CONNECTIONS
        slow_read = (event.protocol == 6 and not slow_http
                     and f['slow_read_connections'] >= slow_read_features.MIN_SLOW_READ_CONNECTIONS)
        slow_exhaustion = slow_http or slow_read
        if event.protocol == 6 and not syn_flood:
            # A frozen synthetic-model posterior or high TCP rate alone is not
            # evidence of a SYN flood in established, high-rate TCP traffic.
            hits.pop('DDOS', None)
        if event.protocol == 17 and not udp_flood:
            # The frozen synthetic model must not infer a UDP flood from volume
            # elsewhere in the enclave or from a low-rate flow summary.
            hits.pop('DDOS', None)
        if event.protocol not in (6, 17) and f['packet_rate'] < 1000:
            # ICMP and other protocols: the frozen synthetic model alone cannot raise a flood alert.
            hits.pop('DDOS', None)
        if event.transport == 'IP':
            # Port 443 alone is not an observed TLS/QUIC session: the synthetic model's
            # posterior cannot raise encrypted-malware suspicion without handshake or
            # QUIC metadata. Rule and fingerprint paths below are unaffected.
            hits.pop('ENCRYPTED_MALWARE', None)
        # The synthetic model's DNS posterior alone does not generalize to real
        # domains. Require the existing lexical rule for DGA alerts, measuring
        # length on the same first label as entropy and bigram surprise.
        dga_evidence = conservative_rule(f)
        tunnel_reason = candidate_reason(f) if self.dns_tunnel_candidate else None
        if self.dns_tunnel_candidate:
            # Keep synthetic-model DNS hits out of development comparisons.
            hits.pop('DNS_TUNNELLING', None)
        if self.dga_model.enabled:
            # DGA uses its independent lexical classifier after quality gates.
            # Synthetic model hits and the old length rule cannot override it.
            hits.pop('DGA_DOMAINS', None)
            dga_score = self.dga_model.predict(event.dns_name)
            if dga_score is not None and dga_score >= self.dga_model.threshold:
                hits['DGA_DOMAINS'] = (dga_score, DetectorType.ML)
        tls_indicator = tls_indicators.indicator_match(f, self.tls_indicators) if event.encrypted else None
        tls_behaviour = event.encrypted and tls_indicators.behaviour_match(f)
        # Handshake-list and behaviour paths supplement the frozen lab-fingerprint feature.
        tls_session_path = bool(tls_indicator or tls_behaviour) and not f['fingerprint_risk']
        rules = {
            'DDOS': (syn_flood or slow_exhaustion) if event.protocol == 6 else udp_flood if event.protocol == 17 else f['packet_rate'] >= 1000,
            'RECONNAISSANCE': max(f['destination_count'], f['port_count']) >= thresholds.RECON_MIN_FANOUT,
            'DNS_TUNNELLING': bool(tunnel_reason) if self.dns_tunnel_candidate else f['domain_label_length'] >= 50 and f['txt_record'] == 1,
            'DGA_DOMAINS': dga_evidence and not self.dga_model.enabled,
            'BOTNET_C2': (f['history_count'] >= thresholds.C2_MIN_HISTORY and f['iat_mean'] >= thresholds.C2_MIN_IAT_MEAN_S
                          and f['iat_cv'] < thresholds.C2_MAX_IAT_CV),
            'ENCRYPTED_MALWARE': f['encrypted'] and (f['fingerprint_risk'] or tls_session_path),
            'DATA_EXFILTRATION': f['source_forward_bytes_60s'] > thresholds.EXFIL_BYTES_60S,
        }
        for threat, matched in rules.items():
            if matched:
                hits[threat] = (hits[threat][0], DetectorType.HYBRID) if threat in hits else (.8, DetectorType.RULE)
        alerts = []
        self.dedup = {k: t for k, t in self.dedup.items() if event.timestamp - t < 30000}
        for threat, (score, source) in hits.items():
            if threat == 'RECONNAISSANCE' and max(f['destination_count'], f['port_count']) < thresholds.RECON_ALERT_FLOOR:
                continue
            if threat == 'RECONNAISSANCE' and (event.dst_ip.is_multicast or str(event.dst_ip) == '255.255.255.255'
                                               or (0 < event.src_port < 1024 and not event.syn)):
                # Scans target unicast hosts from ephemeral ports; replies from a service port
                # (for example a DNS resolver) and multicast name services are not scans.
                continue
            if threat == 'BOTNET_C2' and f['history_count'] < thresholds.C2_MIN_HISTORY:
                continue
            if threat == 'BOTNET_C2' and (event.dst_ip.is_multicast or str(event.dst_ip) == '255.255.255.255'):
                # Multicast/broadcast name services (LLMNR, mDNS, NetBIOS) are never a C2 server.
                continue
            if threat == 'ENCRYPTED_MALWARE' and not event.encrypted:
                continue
            if threat in ('DGA_DOMAINS', 'DNS_TUNNELLING') and not event.dns_name:
                continue
            if threat == 'DGA_DOMAINS' and (event.dns_name or '').lower().startswith('xn--'):
                # An internationalized (punycode) first label is an encoding, not a generated-domain signal.
                continue
            if threat == 'DGA_DOMAINS' and not self.dga_model.enabled and not dga_evidence:
                continue
            key = ((str(event.src_ip), threat) if threat == 'RECONNAISSANCE'
                   else (str(event.dst_ip), threat) if threat == 'DDOS' and (syn_flood or udp_flood)
                   else (str(event.src_ip), str(event.dst_ip), threat))
            if key in self.dedup:
                continue
            if len(self.dedup) >= 4096:
                self.dedup.pop(next(iter(self.dedup)))
            self.dedup[key] = event.timestamp
            evidence_keys = (DNS_TUNNEL_FEATURES if threat == 'DNS_TUNNELLING' and self.dns_tunnel_candidate
                             else tls_indicators.EVIDENCE if threat == 'ENCRYPTED_MALWARE' and tls_session_path
                             else slow_http_features.EVIDENCE if threat == 'DDOS' and slow_http and not syn_flood
                             else slow_read_features.EVIDENCE if threat == 'DDOS' and slow_read and not syn_flood
                             else EVIDENCE[threat])
            evidence = {k: f[k] for k in evidence_keys}
            if threat == 'DDOS' and syn_flood:
                evidence.update(packet_rate=f['syn_target_packet_rate'],
                                global_packet_rate=f['packet_rate'],
                                syn_fraction=f['syn_target_fraction'],
                                syn_fraction_basis=f['syn_target_fraction_basis'],
                                source_entropy=f['syn_target_source_entropy'],
                                source_count_lower_bound=f['syn_target_source_count_lower_bound'],
                                source_entropy_partial=f['syn_target_entropy_partial'],
                                syn_target='destination_tcp')
            if threat == 'DDOS' and udp_flood:
                evidence.update(packet_rate=f['udp_target_packet_rate'],
                                byte_rate=f['udp_target_byte_rate'],
                                global_packet_rate=f['packet_rate'],
                                source_entropy=f['udp_target_source_entropy'],
                                source_count_lower_bound=f['udp_target_source_count_lower_bound'],
                                source_entropy_partial=f['udp_target_entropy_partial'],
                                destination_concentration=f['udp_destination_concentration'],
                                mean_packet_bytes=f['udp_packet_size_mean'],
                                packet_size_cv=f['udp_packet_size_cv'],
                                packet_size_basis=f['udp_packet_size_basis'],
                                udp_target='destination_udp')
            spoof_evidence = None
            if threat == 'DDOS' and (syn_flood or udp_flood):
                tracked = (self.extractor.syn_targets if event.protocol == 6 else self.extractor.udp_targets)
                window = tracked.get(str(event.dst_ip))
                spoof_evidence = spoof_indicators.reserved_sources(window.sources) if window else None
                if spoof_evidence:
                    evidence.update(spoof_evidence)
            if threat == 'DDOS' and slow_exhaustion and not syn_flood:
                evidence['ddos_subtype'] = 'slow_http' if slow_http else 'slow_read'
            if threat == 'ENCRYPTED_MALWARE' and tls_session_path:
                evidence['tls_basis'] = (f'indicator_{tls_indicator[0]}' if tls_indicator
                                         else 'rare_fingerprint_regular_session')
                if tls_indicator:
                    evidence['tls_indicator_note'] = tls_indicator[2]
            if threat == 'DNS_TUNNELLING' and self.dns_tunnel_candidate:
                evidence['dns_candidate_pattern'] = tunnel_reason
            if threat == 'DATA_EXFILTRATION':
                evidence.update(egress_bytes=f['source_forward_bytes_60s'],
                                source_forward_byte_rate_10s=f['source_forward_byte_rate_10s'],
                                source_byte_window_resolution_ms=f['source_byte_window_resolution_ms'],
                                egress_basis='observed_source_forward_bytes_60s',
                                observed_byte_ratio_status=f['observed_byte_ratio_status'])
            evidence['confidence_kind'] = 'heuristic strength' if source == DetectorType.RULE else 'synthetic-trained model posterior'
            if threat == 'DGA_DOMAINS':
                evidence['observed_dns_name'] = event.dns_name
                if self.dga_model.enabled:
                    evidence['confidence_kind'] = self.dga_model.data['confidence_kind']
                    evidence['dga_label'] = domain_label(event.dns_name)
                    evidence['dga_threshold'] = self.dga_model.threshold
                    evidence['dga_feature_version'] = FEATURE_VERSION
            evidence['window_partial'] = f['window_partial']
            narrative = '; '.join(f'{k}={round(v, 4) if isinstance(v, float) else v}' for k, v in evidence.items())
            if threat == 'DDOS' and udp_flood:
                narrative += ('; consistent with UDP reflection/amplification behavior; '
                              'passive metadata cannot verify reflection or amplification factor'
                              if f['udp_target_source_count_lower_bound'] >= 16 and f['udp_packet_size_mean'] >= 512
                              else '; high-rate UDP pattern; passive metadata cannot verify reflection or amplification')
            if spoof_evidence:
                narrative += ('; reserved or martian source addresses among flood sources, a passive '
                              'indicator of forged sources that cannot prove forgery')
            if threat == 'DDOS' and slow_http and not syn_flood:
                narrative += ('; many long-lived low-rate connections held open to one service, '
                              'consistent with slow-HTTP exhaustion; request contents not inspected')
            if threat == 'DDOS' and slow_read and not syn_flood:
                narrative += ('; many connections held open with a tiny advertised receive window, '
                              'consistent with a slow-read attack; contents not inspected')
            if threat == 'DATA_EXFILTRATION':
                narrative += '; behavior consistent with possible exfiltration; content and intent unverified'
                if not event.reverse_observed:
                    narrative += '; reverse traffic unavailable: volume-only suspicion'
                elif event.reverse_bytes == 0:
                    narrative += '; reverse observed as zero: finite byte ratio undefined'
            if threat == 'ENCRYPTED_MALWARE' and tls_session_path:
                narrative += ('; metadata-only suspicion from handshake fingerprints and session size/timing; '
                              'payload not decrypted; not proof of malware')
            elif threat == 'ENCRYPTED_MALWARE':
                narrative += '; metadata-only suspicion; lab fingerprint, not proof of malware'
            severity = Severity.CRITICAL if threat == 'DDOS' else Severity.HIGH if threat in ('ENCRYPTED_MALWARE', 'DATA_EXFILTRATION', 'BOTNET_C2') else Severity.MEDIUM
            alerts.append(AlertEvent.create(fid, ThreatClass(threat), score, severity, narrative,
                          str(event.src_ip), str(event.dst_ip), event.protocol, event.src_port,
                          event.dst_port, source, timestamp=event.timestamp, raw_evidence_metrics=evidence))
        return alerts

    def telemetry(self):
        timings = sorted(self.latencies)
        return dict(processed=self.processed, late_events=self.extractor.late_events,
                    state_evictions=self.extractor.evictions, active_sources=len(self.extractor.sources),
                    dga_detector='public-lexical-model' if self.dga_model.enabled else 'conservative-lexical-guard',
                    dga_candidate_enabled=self.dga_model.enabled,
                    dns_tunnel_candidate_enabled=self.dns_tunnel_candidate,
                    rate_window_resolution_ms=self.extractor.global_rates.resolution_ms,
                    source_entropy_partial=bool(self.extractor.global_rates.sources.get(None)),
                    processing_p95_ms=timings[min(len(timings)-1, int(len(timings)*.95))] if timings else 0)

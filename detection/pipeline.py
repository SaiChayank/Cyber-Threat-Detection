"""Incremental passive inference. No networking operations."""
import time
from collections import deque, OrderedDict
from features.extractor import FeatureExtractor
from ml.model import Model
from ml.dga import DgaModel, domain_label, FEATURE_VERSION
from detection.dga_rules import conservative_rule
from detection.dns_tunnel_candidate import candidate_reason
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
        self.sessions = OrderedDict()
        self.dns_tunnel_candidate = dns_tunnel_candidate

    def flow_id(self, event):
        if event.flow_id:
            return event.flow_id
        key = (str(event.src_ip), str(event.dst_ip), event.src_port, event.dst_port, event.protocol)
        previous = self.sessions.pop(key, None)
        start = previous[0] if previous and event.timestamp - previous[1] < 60000 else event.timestamp
        self.sessions[key] = (start, event.timestamp)
        if len(self.sessions) > 4096:
            self.sessions.popitem(last=False)
        return FlowRecord.compute_flow_id(*key, start)

    def process(self, event):
        started = time.perf_counter()
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
        if event.protocol == 6 and not syn_flood:
            # A frozen synthetic-model posterior or high TCP rate alone is not
            # evidence of a SYN flood in established, high-rate TCP traffic.
            hits.pop('DDOS', None)
        if event.protocol == 17 and not udp_flood:
            # The frozen synthetic model must not infer a UDP flood from volume
            # elsewhere in the enclave or from a low-rate flow summary.
            hits.pop('DDOS', None)
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
        rules = {
            'DDOS': syn_flood if event.protocol == 6 else udp_flood if event.protocol == 17 else f['packet_rate'] >= 1000,
            'RECONNAISSANCE': max(f['destination_count'], f['port_count']) >= 20,
            'DNS_TUNNELLING': bool(tunnel_reason) if self.dns_tunnel_candidate else f['domain_label_length'] >= 50 and f['txt_record'] == 1,
            'DGA_DOMAINS': dga_evidence and not self.dga_model.enabled,
            'BOTNET_C2': f['history_count'] >= 8 and f['iat_mean'] >= 1 and f['iat_cv'] < .05,
            'ENCRYPTED_MALWARE': f['encrypted'] and f['fingerprint_risk'],
            'DATA_EXFILTRATION': f['source_forward_bytes_60s'] > 20000000,
        }
        for threat, matched in rules.items():
            if matched:
                hits[threat] = (hits[threat][0], DetectorType.HYBRID) if threat in hits else (.8, DetectorType.RULE)
        alerts = []
        self.dedup = {k: t for k, t in self.dedup.items() if event.timestamp - t < 30000}
        for threat, (score, source) in hits.items():
            if threat == 'RECONNAISSANCE' and max(f['destination_count'], f['port_count']) < 10:
                continue
            if threat == 'BOTNET_C2' and f['history_count'] < 8:
                continue
            if threat == 'ENCRYPTED_MALWARE' and not event.encrypted:
                continue
            if threat in ('DGA_DOMAINS', 'DNS_TUNNELLING') and not event.dns_name:
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
            evidence_keys = DNS_TUNNEL_FEATURES if threat == 'DNS_TUNNELLING' and self.dns_tunnel_candidate else EVIDENCE[threat]
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
            if threat == 'DATA_EXFILTRATION':
                narrative += '; behavior consistent with possible exfiltration; content and intent unverified'
                if not event.reverse_observed:
                    narrative += '; reverse traffic unavailable: volume-only suspicion'
                elif event.reverse_bytes == 0:
                    narrative += '; reverse observed as zero: finite byte ratio undefined'
            if threat == 'ENCRYPTED_MALWARE':
                narrative += '; metadata-only suspicion; lab fingerprint, not proof of malware'
            severity = Severity.CRITICAL if threat == 'DDOS' else Severity.HIGH if threat in ('ENCRYPTED_MALWARE', 'DATA_EXFILTRATION', 'BOTNET_C2') else Severity.MEDIUM
            alerts.append(AlertEvent.create(fid, ThreatClass(threat), score, severity, narrative,
                          str(event.src_ip), str(event.dst_ip), event.protocol, event.src_port,
                          event.dst_port, source, timestamp=event.timestamp, raw_evidence_metrics=evidence))
        self.latencies.append((time.perf_counter()-started)*1000)
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

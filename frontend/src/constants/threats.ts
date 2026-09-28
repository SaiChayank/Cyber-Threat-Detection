import { Activity, Radio, Globe2, LockKeyhole, ScanLine, ArrowUpRight, Network } from 'lucide-react'

export const threats = [
  {
    id: 'DDOS',
    icon: Activity,
    name: 'DDoS & floods',
    title: 'Spot the surge.',
    description:
      'Flow rates, SYN patterns and source-IP entropy expose suspicious floods and amplification behavior.',
    signals: ['Flow-level rates', 'SYN statistics', 'Source-IP entropy'],
  },
  {
    id: 'BOTNET_C2',
    icon: Radio,
    name: 'Botnet beaconing',
    title: 'Find the rhythm.',
    description:
      'Repeated connections and regular inter-arrival timing reveal possible command-and-control beaconing.',
    signals: ['Connection periodicity', 'Inter-arrival timing', 'Repeated destinations'],
  },
  {
    id: 'DGA_DOMAINS',
    icon: Globe2,
    name: 'DNS anomalies',
    title: 'Read between the queries.',
    description:
      'Domain entropy and query-length anomalies support DGA and DNS tunnelling detection: two modules within one threat category.',
    signals: ['Domain entropy', 'Query length', 'TXT / NULL records'],
  },
  {
    id: 'ENCRYPTED_MALWARE',
    icon: LockKeyhole,
    name: 'Encrypted sessions',
    title: 'Patterns, without payloads.',
    description:
      'TLS fingerprints and encrypted packet-size and timing patterns flag suspicious sessions. Encrypted payloads remain opaque.',
    signals: ['TLS fingerprints', 'Packet-size patterns', 'Session timing'],
  },
  {
    id: 'RECONNAISSANCE',
    icon: ScanLine,
    name: 'Reconnaissance',
    title: 'Notice the fan-out.',
    description:
      'A single source reaching many destination ports or hosts can indicate reconnaissance and port scanning.',
    signals: ['Destination fan-out', 'Port diversity', 'Source behavior'],
  },
  {
    id: 'DATA_EXFILTRATION',
    icon: ArrowUpRight,
    name: 'Data exfiltration',
    title: 'Follow the imbalance.',
    description:
      'Outbound volume and byte-ratio anomalies identify possible exfiltration. Directional ratios are available only when reverse traffic is observed.',
    signals: ['Outbound volume', 'Directional byte ratios', 'Asymmetric flows'],
  },
]
export const detectionModules = [
  ...threats.slice(0, 2),
  { ...threats[2], name: 'DGA domains' },
  { id: 'DNS_TUNNELLING', name: 'DNS tunnelling', icon: Network },
  ...threats.slice(3),
]
export const threatName = (id: string) =>
  id === 'BENIGN'
    ? 'Benign baseline'
    : detectionModules.find((t) => t.id === id)?.name || id.replaceAll('_', ' ')

"""Fixed local public-source replay presets; never arbitrary server paths."""
from itertools import islice
from datasets.download import ROOT
from datasets.domains import replay_domains
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader

PRESETS = {
    'PUBLIC_DNS_BENIGN': ('CIC DNS: benign capture', 'data/raw/cicdns2021/pcaps/benign/benign_1.pcap'),
    'PUBLIC_DNS_LIGHT': ('CIC DNS: light exfiltration capture', 'data/raw/cicdns2021/pcaps/light/light_audio.pcap'),
    'PUBLIC_DNS_HEAVY': ('CIC DNS: heavy exfiltration capture', 'data/raw/cicdns2021/pcaps/heavy/heavy_audio.pcap'),
    'PUBLIC_DGA': ('UMUDGA: real domain strings, simulated DNS stream', 'data/raw/umudga/corebot.txt'),
}


def records(preset):
    path = ROOT / PRESETS[preset][1]
    if not path.is_file():
        raise FileNotFoundError('Public source is not downloaded/prepared; see docs/DATASETS.md')
    if preset == 'PUBLIC_DGA':
        yield from islice(replay_domains(path), 2000)
    else:
        def packets():
            for batch in PcapReader().read_packets(path):
                for flow, dns, tls in batch:
                    yield from_packet(flow, dns, tls)
        yield from islice(packets(), 2000)


def available():
    return [dict(id=k, name=v[0], ready=(ROOT/v[1]).is_file(), event_limit=2000, model='Existing synthetic-trained pipeline; external replay, not public-trained production model') for k,v in PRESETS.items()]

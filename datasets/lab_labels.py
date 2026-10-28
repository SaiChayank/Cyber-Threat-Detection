"""Ground truth for operator-supplied lab captures. Read-only; captures are never modified.

A label file describes one capture (classic Ethernet PCAP or TrafficEvent JSONL)
as labelled episodes. An observed event belongs to an episode when its timestamp
is inside the episode window and its source or destination is one of the
episode hosts. Events matching no episode are unlabelled benign background.
"""
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from schemas.enums import ThreatClass

FORMAT = 'ps26145-lab-labels/1'
LABELS = frozenset(['BENIGN', *(threat.value for threat in ThreatClass)])
SPLITS = ('train', 'validation', 'test', 'unassigned')
CAPTURE_SUFFIXES = ('.pcap', '.jsonl')


class LabelError(ValueError):
    """The label file cannot be used as ground truth."""


@dataclass(frozen=True)
class Episode:
    id: str
    label: str
    scenario: str
    start_ms: float
    end_ms: float
    hosts: tuple  # ip_network objects; empty matches any endpoint in the window
    tool: str | None = None

    def matches(self, event):
        if not self.start_ms <= event.timestamp <= self.end_ms:
            return False
        return not self.hosts or any(ip in network for ip in (event.src_ip, event.dst_ip)
                                     for network in self.hosts)


@dataclass(frozen=True)
class CaptureLabels:
    path: Path
    capture: Path
    split: str
    episodes: tuple

    def matching(self, event):
        return [episode for episode in self.episodes if episode.matches(event)]


def _time_ms(entry, key, where):
    if f'{key}_ms' in entry:
        value = entry[f'{key}_ms']
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise LabelError(f'{where}: {key}_ms must be nonnegative epoch milliseconds')
        return float(value)
    if key in entry:
        try:
            moment = datetime.fromisoformat(str(entry[key]).replace('Z', '+00:00'))
        except ValueError as exc:
            raise LabelError(f'{where}: {key} must be ISO-8601') from exc
        if moment.tzinfo is None:
            raise LabelError(f'{where}: {key} needs an explicit UTC offset')
        return moment.timestamp() * 1000
    raise LabelError(f'{where}: missing {key} or {key}_ms')


def _text(entry, key, where, default=None):
    value = entry.get(key, default)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise LabelError(f'{where}: {key} must be a nonempty string')
    return value


def _episode(entry, where):
    if not isinstance(entry, dict):
        raise LabelError(f'{where}: episode must be an object')
    episode_id = _text(entry, 'id', where)
    if episode_id is None:
        raise LabelError(f'{where}: missing id')
    label = entry.get('label')
    if label not in LABELS:
        raise LabelError(f'{where}: label must be one of {sorted(LABELS)}')
    start, end = _time_ms(entry, 'start', where), _time_ms(entry, 'end', where)
    if end < start:
        raise LabelError(f'{where}: end precedes start')
    hosts = entry.get('hosts', [])
    if not isinstance(hosts, list):
        raise LabelError(f'{where}: hosts must be a list of IP addresses or CIDR networks')
    try:
        networks = tuple(ipaddress.ip_network(host, strict=False) for host in hosts)
    except (TypeError, ValueError) as exc:
        raise LabelError(f'{where}: invalid host {exc}') from exc
    return Episode(id=episode_id, label=label,
                   scenario=_text(entry, 'scenario', where, label.lower()),
                   start_ms=start, end_ms=end, hosts=networks,
                   tool=_text(entry, 'tool', where))


def load(path):
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabelError(f'{path}: unreadable label file ({exc})') from exc
    if not isinstance(data, dict) or data.get('format') != FORMAT:
        raise LabelError(f'{path}: format must be {FORMAT!r}')
    capture = _text(data, 'capture', str(path))
    if capture is None:
        raise LabelError(f'{path}: missing capture')
    capture_path = path.parent / capture
    if capture_path.suffix.lower() not in CAPTURE_SUFFIXES:
        raise LabelError(f'{path}: capture must be one of {CAPTURE_SUFFIXES}')
    if not capture_path.is_file():
        raise LabelError(f'{path}: capture not found: {capture_path}')
    split = data.get('split', 'unassigned')
    if split not in SPLITS:
        raise LabelError(f'{path}: split must be one of {SPLITS}')
    entries = data.get('episodes')
    if not isinstance(entries, list):
        raise LabelError(f'{path}: episodes must be a list')
    episodes = tuple(_episode(entry, f'{path}: episodes[{index}]') for index, entry in enumerate(entries))
    ids = [episode.id for episode in episodes]
    if len(ids) != len(set(ids)):
        raise LabelError(f'{path}: episode ids must be unique')
    return CaptureLabels(path=path, capture=capture_path, split=split, episodes=episodes)

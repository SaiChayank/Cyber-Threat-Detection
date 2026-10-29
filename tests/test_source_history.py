"""SourceHistory and CowMap must answer exactly what the full scans they replaced answered."""
import random

import pytest

from features.cow_map import CowMap
from features.source_history import WINDOW_MS, SourceHistory
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def make_events(count, seed):
    rng = random.Random(seed)
    t, events = START, []
    for _ in range(count):
        t += rng.choice([1, 5, 50, 400, 3000, 12000, 70000]) if rng.random() < .2 else rng.randint(1, 200)
        events.append(TrafficEvent(timestamp=t, src_ip='10.0.0.1', dst_ip=f'192.0.2.{rng.randint(1, 5)}',
                                   dst_port=rng.choice([80, 443, 53]), protocol=6, bytes=rng.randint(40, 1500),
                                   syn=rng.random() < .3))
    return events


def reference(events, event, maxlen):
    """Original full scans over the retained deque."""
    retained = events[-maxlen:] if maxlen else events
    recent = [e for e in retained if e.timestamp >= event.timestamp - WINDOW_MS]
    peer = [e for e in retained if e.dst_ip == event.dst_ip and e.dst_port == event.dst_port]
    return dict(total=sum(e.bytes for e in retained), recent_len=len(recent), syn=sum(e.syn for e in recent),
                dst=len({e.dst_ip for e in recent}), ports=len({e.dst_port for e in recent}), peer=peer)


@pytest.mark.parametrize('seed, maxlen', [(1, 512), (2, 8), (3, 3), (4, 64)])
def test_aggregates_match_full_scans_through_expiry_and_eviction(seed, maxlen):
    history, kept = SourceHistory(maxlen), []
    for event in make_events(1500, seed):
        while history and history[0].timestamp < event.timestamp - 60000:
            history.popleft()
            kept.pop(0)
        if len(kept) >= maxlen:
            kept.pop(0)
        history.append(event)
        kept.append(event)
        expected = reference(kept, event, None)
        assert list(history) == kept and len(history) == len(kept)
        assert history.total_bytes == expected['total']
        assert (len(history.recent), history.recent_syn) == (expected['recent_len'], expected['syn'])
        assert (len(history.recent_dst), len(history.recent_ports)) == (expected['dst'], expected['ports'])
        assert list(history.peer(event)) == expected['peer']


def test_forks_are_independent_of_the_original():
    history = SourceHistory(16)
    events = make_events(40, 9)
    for event in events[:20]:
        history.append(event)
    snapshot = (list(history), history.total_bytes, history.recent_syn, dict(history.recent_dst),
                {k: list(v) for k, v in history.peers.items()})
    fork = history.copy()
    for event in events[20:]:
        fork.append(event)
    assert (list(history), history.total_bytes, history.recent_syn, dict(history.recent_dst),
            {k: list(v) for k, v in history.peers.items()}) == snapshot
    assert len(fork) == 16


def test_cow_map_is_an_exact_lru_with_independent_forks():
    rng = random.Random(5)
    lru, model = CowMap(7), {}  # model: insertion-ordered dict used as LRU
    for step in range(3000):
        key = rng.randint(0, 12)
        if rng.random() < .15:
            lru.delete(key)
            model.pop(key, None)
        else:
            lru.set(key, step)
            model.pop(key, None)
            model[key] = step
            while len(model) > 7:
                model.pop(next(iter(model)))
        if step % 97 == 0:
            frozen = dict(lru.items())
            branch = lru.fork()
            branch.set(99, -1)
            branch.delete(next(iter(model)) if model else 0)
            assert dict(lru.items()) == frozen  # The original is untouched by the branch.
        assert len(lru) == len(model) and dict(lru.items()) == model
        assert lru.keys() == list(model)  # Same recency order.
        assert lru.values() == list(model.values())


def test_cow_map_oldest_pop_and_unbounded_capacity():
    unbounded = CowMap(None)
    for key in range(500):
        unbounded.set(key, key)
    unbounded.set(0, 'touched')
    assert len(unbounded) == 501 - 1 and unbounded.popitem_oldest() == (1, 1)
    assert unbounded.get(0) == 'touched' and 1 not in unbounded

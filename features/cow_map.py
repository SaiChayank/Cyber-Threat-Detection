"""Bounded copy-on-write map for failure-safe staged state.

fork() is O(delta), not O(size): a staged copy shares the immutable base and
holds only its own small delta, so a failed event is discarded without ever
copying the full table. The delta is folded into a fresh base every FLATTEN
writes. Values must be treated as immutable (replace, never mutate in place).
Overflow evicts the oldest-inserted key (FIFO).
"""
FLATTEN = 128
_GONE = object()


class CowMap:
    __slots__ = ('base', 'delta', 'size', 'capacity')

    def __init__(self, capacity, base=None, delta=None, size=0):
        self.capacity = capacity
        self.base = base if base is not None else {}
        self.delta = delta if delta is not None else {}
        self.size = size

    def fork(self):
        return CowMap(self.capacity, self.base, self.delta.copy(), self.size)

    def get(self, key, default=None):
        value = self.delta.get(key, self.base.get(key, default))
        return default if value is _GONE else value

    def __getitem__(self, key):
        value = self.get(key, _GONE)
        if value is _GONE:
            raise KeyError(key)
        return value

    def __contains__(self, key):
        return self.get(key, _GONE) is not _GONE

    def __len__(self):
        return self.size

    def set(self, key, value):
        if key not in self:
            self.size += 1
        self.delta[key] = value
        if len(self.delta) >= FLATTEN:
            self._flatten()
        while self.size > self.capacity:
            self._evict_oldest()

    def delete(self, key):
        if key in self:
            self.size -= 1
            self.delta[key] = _GONE

    def _flatten(self):
        merged = {k: v for k, v in self.base.items() if k not in self.delta}
        merged.update((k, v) for k, v in self.delta.items() if v is not _GONE)
        self.base, self.delta = merged, {}

    def _evict_oldest(self):
        self._flatten()
        del self.base[next(iter(self.base))]
        self.size -= 1

    def items(self):
        merged = {k: v for k, v in self.base.items() if k not in self.delta}
        merged.update((k, v) for k, v in self.delta.items() if v is not _GONE)
        return merged.items()

    def keys(self):
        return [k for k, _ in self.items()]

    def __iter__(self):
        return iter(self.keys())

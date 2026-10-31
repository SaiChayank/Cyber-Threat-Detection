"""Whether two addresses are on the same local network (private pair, or same IPv4 /24)."""


def same_local_network(a, b):
    if a.is_private and b.is_private:
        return True
    return a.version == 4 and b.version == 4 and (int(a) >> 8) == (int(b) >> 8)

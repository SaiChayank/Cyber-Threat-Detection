"""Passive source-forgery indicator for flood alerts: reserved or martian sources.

Loopback, multicast, unspecified, link-local and reserved (240/4)
addresses never legitimately originate traffic on a monitored link, so a share of
them among a flood's sources suggests forged source addresses. Private (RFC 1918)
sources are NOT counted: internal networks use them legitimately. The indicator is
evidence only. Passive metadata cannot prove forgery, so it never changes whether
an alert fires, and absence of reserved sources proves nothing.
"""
import ipaddress

MIN_SOURCES = 4


def reserved_sources(sources):
    """Evidence dict when any tracked flood source is reserved, else None."""
    total = reserved = 0
    for source in sources:
        if source is None:  # Overflow identity group carries no address.
            continue
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            continue
        total += 1
        reserved += (address.is_loopback or address.is_multicast or address.is_unspecified
                     or address.is_link_local or address.is_reserved)
    if total < MIN_SOURCES or not reserved:
        return None
    return dict(source_reserved_count=reserved, source_reserved_fraction=round(reserved / total, 4),
                source_reserved_basis='tracked_flood_sources')

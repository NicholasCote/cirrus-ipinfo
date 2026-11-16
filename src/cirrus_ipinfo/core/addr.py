"""Address helpers shared by every layer."""

from __future__ import annotations

import ipaddress
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def normalize(value: str | IPAddress) -> IPAddress:
    """Parse an address and fold IPv4-mapped IPv6 (``::ffff:a.b.c.d``) to IPv4.

    Dual-stack listeners (Traefik included) can report IPv4 clients in mapped
    form. Without folding, every such client would land in the IANA
    ``::ffff:0:0/96`` special-purpose block and get no enrichment.
    Zone IDs (``fe80::1%eth0``) are stripped.
    """
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        value = value.split("%", 1)[0]
        addr = ipaddress.ip_address(value)
    else:
        addr = value
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def range_to_cidrs(start: IPAddress, end: IPAddress) -> list[IPNetwork]:
    return list(ipaddress.summarize_address_range(start, end))


def span(start: IPAddress, end: IPAddress) -> int:
    return int(end) - int(start) + 1

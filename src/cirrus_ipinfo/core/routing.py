"""Routing layer: announced prefix and origin ASN(s) from a prefix-to-AS table.

Accepted input formats (one prefix per line, ``#`` comments ignored):

* CAIDA RouteViews pfx2as: ``<network>\\t<prefixlen>\\t<asfield>``
* pyasn "ipasn" / generic: ``<network>/<prefixlen>\\t<asfield>``

``asfield`` is one ASN, ``a_b_c`` (multi-origin, MOAS) or ``a,b`` (AS-set).
For both MOAS and AS-sets, ``origin_asns`` keeps every ASN and ``origin_asn``
is the first one listed.

AS names come from RIPE's ``asn.txt`` (``<asn> <name>, <CC>``). They're keyed
by the routing table's origin ASN, so the name always matches the ASN shown.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from .addr import IPAddress
from .rangeindex import DualRangeIndex

MAX_ASN = 4294967295


@dataclass(frozen=True)
class Route:
    prefix: str
    origin_asns: tuple[int, ...]

    @property
    def origin_asn(self) -> int | None:
        return self.origin_asns[0] if self.origin_asns else None


def _parse_asfield(field: str) -> tuple[int, ...]:
    asns: list[int] = []
    for part in field.replace(",", "_").split("_"):
        part = part.strip().upper().removeprefix("AS")
        if not part:
            continue
        if "." in part:  # asdot notation 1.10 -> 65546
            hi, lo = part.split(".", 1)
            n = (int(hi) << 16) + int(lo)
        else:
            n = int(part)
        if 0 <= n <= MAX_ASN and n not in asns:
            asns.append(n)
    return tuple(asns)


def parse_pfx2as(lines: Iterable[str]) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Route]]:
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if "/" in parts[0]:
            net = ipaddress.ip_network(parts[0], strict=False)
            asfield = parts[1]
        else:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            asfield = parts[2]
        asns = _parse_asfield(asfield)
        if asns:
            out.append((net, Route(str(net), asns)))
    return out


class RoutingTable:
    def __init__(self, routes: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Route]]):
        # Longest-prefix match is exactly "smallest covering range".
        self._index: DualRangeIndex[Route] = DualRangeIndex.from_networks(routes, mode="most_specific")
        self.size = len(routes)

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "RoutingTable":
        return cls(parse_pfx2as(lines))

    def lookup(self, addr: IPAddress) -> Route | None:
        return self._index.lookup(addr)


class AsNames:
    def __init__(self, names: dict[int, str]):
        self._names = names

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "AsNames":
        names: dict[int, str] = {}
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            num, _, rest = line.strip().partition(" ")
            try:
                asn = int(num)
            except ValueError:
                continue
            rest = rest.strip()
            # drop the trailing ", CC" country suffix
            head, sep, tail = rest.rpartition(",")
            if sep and len(tail.strip()) == 2 and tail.strip().isalpha():
                rest = head.strip()
            names[asn] = rest
        return cls(names)

    def get(self, asn: int | None) -> str | None:
        return None if asn is None else self._names.get(asn)

"""RIR extended delegated statistics.

Format (one record per line, ``|``-separated):

    registry|cc|type|start|value|date|status|opaque-id

* the version line starts with a version number (``2|ripencc|...``)
* summary lines have ``summary`` in field 6
* IPv4 ``value`` is an address *count*. It isn't always a power of two, so
  ranges aren't always CIDRs.
* IPv6 ``value`` is a prefix length

This tells us, for any address, which RIR administers it (which decides between
dump and RDAP), its delegation country/date/status, and the opaque holder id.
An opaque-id change for a range is a cheap ownership-change signal.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from ..addr import IPAddress
from ..rangeindex import DualRangeIndex

_RIR_NAMES = {"arin": "arin", "ripencc": "ripencc", "ripe": "ripencc", "apnic": "apnic",
              "lacnic": "lacnic", "afrinic": "afrinic"}


@dataclass(frozen=True)
class Delegation:
    rir: str
    start: IPAddress
    end: IPAddress
    country: str | None
    status: str
    delegated_on: date | None
    opaque_id: str | None


def _date(text: str) -> date | None:
    if not text or text in ("00000000", "") or not text.isdigit() or len(text) != 8:
        return None
    try:
        return date(int(text[:4]), int(text[4:6]), int(text[6:]))
    except ValueError:
        return None


def parse_delegated(lines: Iterable[str]) -> list[Delegation]:
    out: list[Delegation] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split("|")
        if f[0][:1].isdigit():  # version line
            continue
        if len(f) < 7 or f[2] not in ("ipv4", "ipv6") or (len(f) > 5 and f[5] == "summary"):
            continue
        rir = _RIR_NAMES.get(f[0].lower())
        if rir is None:
            continue
        start = ipaddress.ip_address(f[3])
        if f[2] == "ipv4":
            end = ipaddress.ip_address(int(start) + int(f[4]) - 1)
        else:
            end = ipaddress.ip_network(f"{f[3]}/{f[4]}", strict=False).broadcast_address
        status = f[6].lower()
        if status not in ("allocated", "assigned"):
            # "available"/"reserved" ranges carry no holder; skip so they don't
            # shadow anything.
            continue
        cc = f[1].upper() if len(f[1]) == 2 and f[1] != "ZZ" else None
        out.append(Delegation(rir, start, end, cc, status, _date(f[5]), f[7] if len(f) > 7 and f[7] else None))
    return out


class DelegatedStats:
    def __init__(self, delegations: list[Delegation]):
        self._index: DualRangeIndex[Delegation] = DualRangeIndex.build(
            ((d.start, d.end, d) for d in delegations), mode="most_specific"
        )

    @classmethod
    def from_lines(cls, *sources: Iterable[str]) -> "DelegatedStats":
        return cls([d for src in sources for d in parse_delegated(src)])

    def lookup(self, addr: IPAddress) -> Delegation | None:
        return self._index.lookup(addr)

"""Registry network record (maps to the ``network`` table)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..addr import IPAddress, range_to_cidrs, span

# RIRs whose public split database dumps we load locally. ARIN and LACNIC
# have no bulk dump we use, so they always go through RDAP plus the cache.
DUMP_RIRS = frozenset({"ripencc", "apnic", "afrinic"})

# Fields that define "the registry said the same thing". Timestamps of our own
# fetches are deliberately excluded.
_SEMANTIC_FIELDS = (
    "start", "end", "rir", "handle", "parent_handle", "status", "org_handle",
    "org", "netname", "country", "abuse_contact", "registered_at", "rir_last_changed",
)


def _iso(v: datetime | None) -> str | None:
    # Same instant must hash the same whatever offset the registry (or Postgres) used.
    if v is None:
        return None
    return (v.astimezone(UTC) if v.tzinfo else v.replace(tzinfo=UTC)).isoformat()


@dataclass(frozen=True)
class NetworkRecord:
    start: IPAddress
    end: IPAddress
    rir: str
    source: str
    handle: str | None = None
    parent_handle: str | None = None
    status: str | None = None
    org_handle: str | None = None
    org: str | None = None
    netname: str | None = None
    country: str | None = None
    abuse_contact: str | None = None
    registered_at: datetime | None = None
    rir_last_changed: datetime | None = None
    raw: dict | None = field(default=None, compare=False, repr=False, hash=False)

    def __post_init__(self) -> None:
        if self.start.version != self.end.version:
            raise ValueError("mixed-family network range")
        if int(self.end) < int(self.start):
            raise ValueError("network end before start")
        if self.country is not None:
            object.__setattr__(self, "country", self.country.upper() if len(self.country) == 2 else None)

    @property
    def span(self) -> int:
        return span(self.start, self.end)

    @property
    def cidrs(self) -> list[str]:
        return [str(n) for n in range_to_cidrs(self.start, self.end)]

    def contains(self, addr: IPAddress) -> bool:
        return addr.version == self.start.version and int(self.start) <= int(addr) <= int(self.end)

    def semantic(self) -> dict:
        d = {}
        for name in _SEMANTIC_FIELDS:
            v = getattr(self, name)
            if isinstance(v, datetime):
                v = _iso(v)
            elif isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                v = str(v)
            d[name] = v
        return d

    @property
    def content_hash(self) -> bytes:
        blob = json.dumps(self.semantic(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).digest()

"""IANA special-purpose address handling.

Source: the IANA IPv4/IPv6 Special-Purpose Address Registries (CSV), vendored
in ``cirrus_ipinfo/data`` and refreshable from the nightly snapshot.

Rule: an address is *special* (no lookups at all) when the most specific
matching registry entry is not marked ``Globally Reachable = True``. Entries
such as AS112, the PCP/TURN anycast addresses, AMT and ``64:ff9b::/96`` are
globally reachable real-world addresses and are enriched normally. Entries
marked ``N/A`` (Teredo, 6to4) or left blank (deprecated blocks) are treated as
special.

Multicast is not in the special-purpose registries but can never be a
legitimate client source, so it is added here (RFC 5771, RFC 4291).
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from importlib import resources

from .addr import IPAddress
from .rangeindex import DualRangeIndex, parse_network

_FOOTNOTE = re.compile(r"\s*\[\d+\]")


@dataclass(frozen=True)
class SpecialEntry:
    prefix: str
    name: str
    rfc: str
    globally_reachable: str  # "True" | "False" | "N/A" | ""

    @property
    def is_special(self) -> bool:
        return self.globally_reachable != "True"


_EXTRA = [
    SpecialEntry("224.0.0.0/4", "Multicast", "[RFC 5771]", "False"),
    SpecialEntry("ff00::/8", "Multicast", "[RFC 4291]", "False"),
]


def _clean(text: str) -> str:
    return _FOOTNOTE.sub("", text).strip()


def parse_registry_csv(text: str) -> list[SpecialEntry]:
    entries = []
    for row in csv.DictReader(io.StringIO(text)):
        name = _clean(row["Name"]).strip('"')
        reach = _clean(row.get("Globally Reachable") or "")
        for block in _clean(row["Address Block"]).split(","):
            block = block.strip()
            if block:
                entries.append(SpecialEntry(block, name, row.get("RFC", "").strip(), reach))
    return entries


class SpecialPurpose:
    def __init__(self, entries: list[SpecialEntry]):
        self.entries = entries
        self._index: DualRangeIndex[SpecialEntry] = DualRangeIndex.from_networks(
            ((parse_network(e.prefix), e) for e in entries), mode="most_specific"
        )

    @classmethod
    def default(cls) -> "SpecialPurpose":
        pkg = resources.files("cirrus_ipinfo") / "data"
        texts = [(pkg / f).read_text() for f in ("iana-ipv4-special-registry.csv", "iana-ipv6-special-registry.csv")]
        return cls.from_texts(texts)

    @classmethod
    def from_texts(cls, texts: list[str]) -> "SpecialPurpose":
        entries = [e for t in texts for e in parse_registry_csv(t)]
        return cls(entries + _EXTRA)

    def lookup(self, addr: IPAddress) -> SpecialEntry | None:
        """The most specific registry entry covering ``addr`` (special or not)."""
        return self._index.lookup(addr)

    def classify(self, addr: IPAddress) -> str | None:
        """Registry name if ``addr`` must be short-circuited, else None."""
        entry = self.lookup(addr)
        if entry is not None and entry.is_special:
            return entry.name
        return None

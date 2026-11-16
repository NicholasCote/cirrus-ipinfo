"""RIR transfer logs (NRO JSON format) used as an ownership-change signal.

Shape, confirmed against the RIPE NCC ``transfers_latest.json``:

    {"transfers": [{"transfer_date": "2026-11-13T19:00:00Z",
                    "type": "RESOURCE_TRANSFER" | "MERGER_ACQUISITION",
                    "ip4nets": {"original_set": [...], "transfer_set": [{"start_address", "end_address"}]},
                    "ip6nets": {...}, "asns": {...},
                    "source_rir": "RIPE NCC", "recipient_rir": "RIPE NCC", ...}]}

Only ``transfer_set`` matters: those are the addresses that changed hands.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import datetime

from ..addr import IPAddress
from ..rangeindex import DualRangeIndex


def parse_transfers(doc: dict) -> list[tuple[IPAddress, IPAddress, datetime]]:
    out = []
    for t in doc.get("transfers", []):
        when = t.get("transfer_date")
        if not when:
            continue
        ts = datetime.fromisoformat(when.replace("Z", "+00:00"))
        for fam in ("ip4nets", "ip6nets"):
            for r in (t.get(fam) or {}).get("transfer_set", []) or []:
                try:
                    a = ipaddress.ip_address(r["start_address"])
                    b = ipaddress.ip_address(r["end_address"])
                except (KeyError, ValueError):
                    continue
                if a.version == b.version and int(a) <= int(b):
                    out.append((a, b, ts))
    return out


class TransferLog:
    def __init__(self, events: Iterable[tuple[IPAddress, IPAddress, datetime]]):
        self._index: DualRangeIndex[datetime] = DualRangeIndex.build(events, mode="union")

    @classmethod
    def from_docs(cls, *docs: dict) -> "TransferLog":
        return cls([e for d in docs for e in parse_transfers(d)])

    def latest_transfer(self, addr: IPAddress) -> datetime | None:
        dates = self._index.lookup(addr)
        return max(dates) if dates else None

    def transferred_since(self, addr: IPAddress, since: datetime) -> bool:
        latest = self.latest_transfer(addr)
        return latest is not None and latest > since

"""Static IP range index.

Registry objects, routed prefixes, cloud ranges and blocklists are all "ranges
that may nest or overlap". The index flattens them once into sorted,
non-overlapping *elementary segments*, so a lookup is a single bisect.

Two build modes:

* ``most_specific``: each segment carries the value of the smallest covering
  range (ties broken by a caller-supplied priority, then insertion order).
  Used for registry networks, routing (longest-prefix match) and cloud ranges.
* ``union``: each segment carries the frozenset of the values of *all*
  covering ranges. Used for flags such as Tor and blocklist membership.

IPv4 and IPv6 live in separate indexes (``DualRangeIndex``), so addresses of
different families never compare.
"""

from __future__ import annotations

import heapq
import ipaddress
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass
from typing import Any, Generic, Literal, TypeVar

from .addr import IPAddress, IPNetwork

V = TypeVar("V")
Mode = Literal["most_specific", "union"]



class RangeIndex(Generic[V]):
    __slots__ = ("_starts", "_ends", "_values", "mode")

    def __init__(self, starts: list[int], ends: list[int], values: list[Any], mode: Mode):
        self._starts = starts
        self._ends = ends
        self._values = values
        self.mode = mode

    def __len__(self) -> int:
        return len(self._starts)

    @classmethod
    def build(
        cls,
        ranges: Iterable[tuple[int, int, V]],
        mode: Mode = "most_specific",
        priority: Callable[[V], int] | None = None,
    ) -> "RangeIndex[V]":
        items = []
        for seq, (start, end, value) in enumerate(ranges):
            if end < start:
                raise ValueError(f"empty range {start}-{end}")
            items.append((start, end, value, seq))
        if not items:
            return cls([], [], [], mode)
        items.sort(key=lambda it: it[0])

        points = sorted({it[0] for it in items} | {it[1] + 1 for it in items})
        starts: list[int] = []
        ends: list[int] = []
        values: list[Any] = []
        prio = priority or (lambda _v: 0)

        i = 0  # next item to activate
        if mode == "most_specific":
            # heap of (span, priority, seq, end, value); expired entries are dropped lazily
            heap: list[tuple[int, int, int, int, Any]] = []
            for p_idx, p in enumerate(points[:-1]):
                while i < len(items) and items[i][0] == p:
                    s, e, v, seq = items[i]
                    heapq.heappush(heap, (e - s + 1, prio(v), seq, e, v))
                    i += 1
                while heap and heap[0][3] < p:
                    heapq.heappop(heap)
                if not heap:
                    continue
                seg_end = points[p_idx + 1] - 1
                value = heap[0][4]
                if ends and ends[-1] + 1 == p and values[-1] is value:
                    ends[-1] = seg_end
                else:
                    starts.append(p)
                    ends.append(seg_end)
                    values.append(value)
        elif mode == "union":
            active: Counter[Hashable] = Counter()
            expiry: list[tuple[int, int, Any]] = []  # (end, seq, value)
            for p_idx, p in enumerate(points[:-1]):
                while i < len(items) and items[i][0] == p:
                    s, e, v, seq = items[i]
                    active[v] += 1
                    heapq.heappush(expiry, (e, seq, v))
                    i += 1
                while expiry and expiry[0][0] < p:
                    _, _, v = heapq.heappop(expiry)
                    active[v] -= 1
                    if active[v] == 0:
                        del active[v]
                if not active:
                    continue
                seg_end = points[p_idx + 1] - 1
                value = frozenset(active)
                if ends and ends[-1] + 1 == p and values[-1] == value:
                    ends[-1] = seg_end
                else:
                    starts.append(p)
                    ends.append(seg_end)
                    values.append(value)
        else:
            raise ValueError(f"unknown mode {mode!r}")
        return cls(starts, ends, values, mode)

    def lookup_int(self, x: int, default: Any = None) -> Any:
        i = bisect_right(self._starts, x) - 1
        if i >= 0 and x <= self._ends[i]:
            return self._values[i]
        return default


@dataclass
class DualRangeIndex(Generic[V]):
    v4: RangeIndex[V]
    v6: RangeIndex[V]

    @classmethod
    def build(
        cls,
        ranges: Iterable[tuple[IPAddress, IPAddress, V]],
        mode: Mode = "most_specific",
        priority: Callable[[V], int] | None = None,
    ) -> "DualRangeIndex[V]":
        r4: list[tuple[int, int, V]] = []
        r6: list[tuple[int, int, V]] = []
        for start, end, value in ranges:
            if start.version != end.version:
                raise ValueError(f"mixed-family range {start}-{end}")
            (r4 if start.version == 4 else r6).append((int(start), int(end), value))
        return cls(RangeIndex.build(r4, mode, priority), RangeIndex.build(r6, mode, priority))

    @classmethod
    def from_networks(
        cls,
        nets: Iterable[tuple[IPNetwork, V]],
        mode: Mode = "most_specific",
        priority: Callable[[V], int] | None = None,
    ) -> "DualRangeIndex[V]":
        return cls.build(((n.network_address, n.broadcast_address, v) for n, v in nets), mode, priority)

    def lookup(self, addr: IPAddress, default: Any = None) -> Any:
        idx = self.v4 if addr.version == 4 else self.v6
        empty = frozenset() if idx.mode == "union" and default is None else default
        return idx.lookup_int(int(addr), empty)

    def __len__(self) -> int:
        return len(self.v4) + len(self.v6)


def parse_network(text: str) -> IPNetwork:
    """Parse a CIDR, tolerating host bits set (some feeds publish them)."""
    return ipaddress.ip_network(text.strip(), strict=False)

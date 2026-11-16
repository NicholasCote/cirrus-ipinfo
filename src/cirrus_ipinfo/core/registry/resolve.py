"""Registry resolution: dump → cache → RDAP, with re-verification rules.

Decision order for one address:

1. RIR (from delegated stats) has a local dump (RIPE NCC/APNIC/AFRINIC) and the
   dump covers the address → use the most specific dump object. Dumps are
   refreshed nightly, so this is always fresh.
2. Otherwise check the network cache (the ``network`` table in production).
   A cached record is reused unless a refetch reason applies:
     * ``stale``           last verified more than ``max_age`` ago (default 90 days)
     * ``routing_change``  origin ASN or announced prefix differs from the IP's
                           current enrichment version
     * ``transfer``        an RIR transfer log entry covers the address after the
                           record was last verified
     * ``delegation_change`` the delegated-stats record (holder opaque id, status,
                           country) changed since the previous snapshot
3. Missing or due → RDAP, if a client is configured and budget remains.
   * success           → ``resolved`` with the new record
   * budget/rate limit → keep the cached record if there is one (``resolved``,
                         refetch reasons kept so the next run retries),
                         else ``pending``
   * not found / error → cached record if any, else ``failed``
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, Protocol

from ..addr import IPAddress
from ..rangeindex import DualRangeIndex
from .network import DUMP_RIRS, NetworkRecord
from .rdap import (
    RdapBudgetExhausted,
    RdapClient,
    RdapError,
    RdapNotFound,
    RdapRateLimited,
    RdapResult,
)
from .transfers import TransferLog

RegistryStatus = Literal["resolved", "pending", "failed", "not_applicable"]


@dataclass(frozen=True)
class CachedNetwork:
    record: NetworkRecord
    last_verified_at: datetime
    network_id: int | None = None


class NetworkCache(Protocol):
    async def lookup(self, addr: IPAddress) -> CachedNetwork | None: ...
    async def put(self, cached: CachedNetwork) -> None: ...


class InMemoryNetworkCache:
    """Most-specific containment lookup over a mutable set of ranges.

    Ranges are bucketed by /16 (IPv4) or /32 (IPv6) so a lookup scans only
    candidates near the address. Ranges covering too many buckets go to a short
    "wide" list that is always scanned. Used in tests, the API and as the
    per-run overlay over the DB cache.
    """

    _MAX_BUCKETS = 4096

    def __init__(self) -> None:
        self._buckets: dict[tuple[int, int], list[CachedNetwork]] = defaultdict(list)
        self._wide: list[CachedNetwork] = []
        self._by_range: dict[tuple[int, int, int], CachedNetwork] = {}

    @staticmethod
    def _shift(version: int) -> int:
        return 16 if version == 4 else 96

    async def put(self, cached: CachedNetwork) -> None:
        r = cached.record
        key = (r.start.version, int(r.start), int(r.end))
        old = self._by_range.get(key)
        if old is not None:
            self._remove(old)
        self._by_range[key] = cached
        sh = self._shift(r.start.version)
        lo, hi = int(r.start) >> sh, int(r.end) >> sh
        if hi - lo + 1 > self._MAX_BUCKETS:
            self._wide.append(cached)
        else:
            for b in range(lo, hi + 1):
                self._buckets[(r.start.version, b)].append(cached)

    def _remove(self, cached: CachedNetwork) -> None:
        if cached in self._wide:
            self._wide.remove(cached)
            return
        r = cached.record
        sh = self._shift(r.start.version)
        for b in range(int(r.start) >> sh, (int(r.end) >> sh) + 1):
            lst = self._buckets.get((r.start.version, b))
            if lst and cached in lst:
                lst.remove(cached)

    async def lookup(self, addr: IPAddress) -> CachedNetwork | None:
        cands = self._buckets.get((addr.version, int(addr) >> self._shift(addr.version)), []) + self._wide
        best = None
        for c in cands:
            if c.record.contains(addr) and (best is None or c.record.span < best.record.span):
                best = c
        return best


@dataclass(frozen=True)
class RefetchPolicy:
    max_age: timedelta = timedelta(days=90)


@dataclass
class RegistryOutcome:
    status: RegistryStatus
    network: NetworkRecord | None = None
    last_verified_at: datetime | None = None
    source: str | None = None              # ripe_dump | apnic_dump | afrinic_dump | rdap | cache
    refetch_reasons: tuple[str, ...] = ()
    fetched: RdapResult | None = None      # set when RDAP was called successfully this run
    network_id: int | None = None
    error: str | None = None


def refetch_reasons(
    cached: CachedNetwork | None,
    addr: IPAddress,
    *,
    now: datetime,
    policy: RefetchPolicy,
    transfers: TransferLog | None = None,
    routing_changed: bool = False,
    delegation_changed: bool = False,
) -> list[str]:
    if cached is None:
        return ["missing"]
    reasons = []
    if now - cached.last_verified_at > policy.max_age:
        reasons.append("stale")
    if routing_changed:
        reasons.append("routing_change")
    if transfers is not None and transfers.transferred_since(addr, cached.last_verified_at):
        reasons.append("transfer")
    if delegation_changed:
        reasons.append("delegation_change")
    return reasons


@dataclass
class RegistryResolver:
    cache: NetworkCache
    now: datetime
    dumps: DualRangeIndex[NetworkRecord] | None = None
    rdap: RdapClient | None = None
    transfers: TransferLog | None = None
    policy: RefetchPolicy = field(default_factory=RefetchPolicy)

    def __post_init__(self) -> None:
        self._locks: dict[tuple[int, int], asyncio.Lock] = defaultdict(asyncio.Lock)

    @staticmethod
    def _lock_key(addr: IPAddress) -> tuple[int, int]:
        # Serialise lookups per /24 (v4) or /48 (v6): neighbours almost always
        # share a registry object, so the second lookup hits the cache instead
        # of spending RDAP budget.
        return (4, int(addr) >> 8) if addr.version == 4 else (6, int(addr) >> 80)

    async def resolve(
        self,
        addr: IPAddress,
        *,
        rir: str | None,
        routing_changed: bool = False,
        delegation_changed: bool = False,
    ) -> RegistryOutcome:
        if rir in DUMP_RIRS and self.dumps is not None:
            rec = self.dumps.lookup(addr)
            if rec is not None:
                return RegistryOutcome("resolved", rec, self.now, rec.source)

        async with self._locks[self._lock_key(addr)]:
            cached = await self.cache.lookup(addr)
            reasons = refetch_reasons(
                cached, addr, now=self.now, policy=self.policy, transfers=self.transfers,
                routing_changed=routing_changed, delegation_changed=delegation_changed,
            )
            # A record we fetched earlier in this same run is never refetched.
            if cached is not None and cached.last_verified_at >= self.now:
                reasons = []
            if not reasons:
                return RegistryOutcome("resolved", cached.record, cached.last_verified_at, "cache",
                                       network_id=cached.network_id)
            if self.rdap is None:
                return self._fallback(cached, reasons, "pending", None)
            try:
                result = await self.rdap.lookup(addr)
            except (RdapBudgetExhausted, RdapRateLimited) as exc:
                return self._fallback(cached, reasons, "pending", type(exc).__name__)
            except RdapNotFound as exc:
                return self._fallback(cached, reasons, "failed", f"not found: {exc}")
            except RdapError as exc:
                return self._fallback(cached, reasons, "failed", str(exc))

            prev_id = None
            verified = result.fetched_at
            if cached is not None and cached.record.content_hash == result.record.content_hash:
                prev_id = cached.network_id   # unchanged → same network row, bump last_verified_at
            await self.cache.put(CachedNetwork(result.record, max(verified, self.now), prev_id))
            return RegistryOutcome("resolved", result.record, verified, "rdap", tuple(reasons),
                                   fetched=result, network_id=prev_id)

    @staticmethod
    def _fallback(cached: CachedNetwork | None, reasons: list[str], status: RegistryStatus,
                  error: str | None) -> RegistryOutcome:
        if cached is not None:
            return RegistryOutcome("resolved", cached.record, cached.last_verified_at, "cache",
                                   tuple(reasons), network_id=cached.network_id, error=error)
        return RegistryOutcome(status, refetch_reasons=tuple(reasons), error=error)

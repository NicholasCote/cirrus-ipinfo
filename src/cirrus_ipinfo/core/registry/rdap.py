"""Live registry lookups over RDAP (RFC 9082/9083), used only on cache misses.

* Base URLs come from the IANA bootstrap files (``data.iana.org/rdap/ipv4.json``
  and ``ipv6.json``), refreshed nightly into the dataset snapshot.
* Every RIR gets its own token bucket. A 429 is retried after ``Retry-After``
  (capped) or with exponential backoff.
* A per-run *budget* caps total HTTP requests. When it runs out, the caller
  marks the IP ``pending`` and it's retried the next night.
* Redirects are followed, and the RIR is taken from the final URL. Transferred
  legacy space is served by a different RIR than the bootstrap names.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from ..addr import IPAddress
from ..rangeindex import DualRangeIndex, parse_network
from .network import NetworkRecord

RDAP_HOST_TO_RIR = {
    "rdap.arin.net": "arin",
    "rdap.db.ripe.net": "ripencc",
    "rdap.apnic.net": "apnic",
    "rdap.lacnic.net": "lacnic",
    "rdap.afrinic.net": "afrinic",
}

# Conservative starting points (requests/second, burst). RIRs don't all
# publish limits; tune these from the observed 429 metrics.
DEFAULT_RATES: dict[str, tuple[float, int]] = {
    "arin": (2.0, 5),
    "ripencc": (2.0, 5),
    "apnic": (1.0, 3),
    "afrinic": (1.0, 3),
    "lacnic": (0.1, 1),
}

USER_AGENT = "cirrus-ipinfo/0.1 (+RDAP client; cached, rate-limited)"


class RdapError(Exception):
    pass


class RdapNotFound(RdapError):
    pass


class RdapRateLimited(RdapError):
    pass


class RdapBudgetExhausted(RdapError):
    pass


class Bootstrap:
    def __init__(self, services: list[tuple[str, str]]):
        """``services``: (CIDR, base_url) pairs."""
        self._index: DualRangeIndex[str] = DualRangeIndex.from_networks(
            ((parse_network(c), u) for c, u in services), mode="most_specific"
        )

    @classmethod
    def from_docs(cls, *docs: dict) -> "Bootstrap":
        pairs = []
        for doc in docs:
            for prefixes, urls in doc.get("services", []):
                https = [u for u in urls if u.startswith("https://")]
                url = (https or urls)[0]
                if not url.endswith("/"):
                    url += "/"
                pairs.extend((p, url) for p in prefixes)
        return cls(pairs)

    def base_url(self, addr: IPAddress) -> str | None:
        return self._index.lookup(addr)


def rir_from_url(url: str) -> str | None:
    return RDAP_HOST_TO_RIR.get(urlsplit(url).hostname or "")


class TokenBucket:
    def __init__(
        self,
        rate: float,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.rate = rate
        self.capacity = float(burst)
        self.tokens = float(burst)
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
                self._last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await self._sleep((1 - self.tokens) / self.rate)


# ---------------------------------------------------------------- parsing


def _vcard(entity: dict, prop: str) -> str | None:
    card = entity.get("vcardArray")
    if not card or len(card) < 2:
        return None
    for item in card[1]:
        if item and item[0] == prop and len(item) >= 4:
            v = item[3]
            if isinstance(v, list):
                v = " ".join(str(x) for x in v if x)
            return str(v) if v else None
    return None


def _walk_entities(entities: list[dict]):
    for e in entities or []:
        yield e
        yield from _walk_entities(e.get("entities", []))


def _event(doc: dict, action: str) -> datetime | None:
    for ev in doc.get("events", []) or []:
        if ev.get("eventAction") == action and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def parse_rdap_network(doc: dict, rir: str) -> NetworkRecord:
    if doc.get("objectClassName") != "ip network":
        raise RdapError(f"unexpected objectClassName {doc.get('objectClassName')!r}")
    start = ipaddress.ip_address(doc["startAddress"].split("/")[0])
    end = ipaddress.ip_address(doc["endAddress"].split("/")[0])

    org = org_handle = abuse = None
    top = doc.get("entities", []) or []
    for e in top:  # registrant is a direct child of the network
        if "registrant" in (e.get("roles") or []):
            org = _vcard(e, "fn")
            org_handle = e.get("handle")
            break
    for e in _walk_entities(top):
        if "abuse" in (e.get("roles") or []):
            abuse = _vcard(e, "email")
            if abuse:
                break

    status = doc.get("type")
    if not status and doc.get("status"):
        status = ",".join(doc["status"])
    return NetworkRecord(
        start=start,
        end=end,
        rir=rir,
        source="rdap",
        handle=doc.get("handle"),
        parent_handle=doc.get("parentHandle"),
        status=status,
        org_handle=org_handle,
        org=org,
        netname=doc.get("name"),
        country=doc.get("country"),
        abuse_contact=abuse,
        registered_at=_event(doc, "registration"),
        rir_last_changed=_event(doc, "last changed"),
        raw=doc,
    )


# ----------------------------------------------------------------- client


@dataclass
class RdapResult:
    record: NetworkRecord
    url: str
    fetched_at: datetime


class RdapClient:
    def __init__(
        self,
        bootstrap: Bootstrap,
        http: httpx.AsyncClient,
        *,
        rates: dict[str, tuple[float, int]] | None = None,
        budget: int | None = None,
        max_retries: int = 4,
        max_retry_after: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.bootstrap = bootstrap
        self.http = http
        self.budget = budget
        self.max_retries = max_retries
        self.max_retry_after = max_retry_after
        self._sleep = sleep
        self._now = now
        rates = {**DEFAULT_RATES, **(rates or {})}
        self._buckets = {rir: TokenBucket(r, b, clock, sleep) for rir, (r, b) in rates.items()}
        self.stats: Counter[str] = Counter()

    async def lookup(self, addr: IPAddress) -> RdapResult:
        base = self.bootstrap.base_url(addr)
        if base is None:
            raise RdapNotFound(f"no RDAP service for {addr}")
        rir = rir_from_url(base)
        bucket = self._buckets.get(rir or "", None)
        url = f"{base}ip/{addr}"

        for attempt in range(self.max_retries + 1):
            if self.budget is not None and self.stats["requests"] >= self.budget:
                self.stats["budget_exhausted"] += 1
                raise RdapBudgetExhausted()
            if bucket is not None:
                await bucket.acquire()
            self.stats["requests"] += 1
            self.stats[f"requests.{rir}"] += 1
            try:
                resp = await self.http.get(
                    url,
                    headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
                    follow_redirects=True,
                )
            except httpx.HTTPError as exc:
                self.stats["errors"] += 1
                if attempt == self.max_retries:
                    raise RdapError(str(exc)) from exc
                await self._sleep(min(2**attempt, self.max_retry_after))
                continue

            if resp.status_code == 429:
                self.stats["http_429"] += 1
                self.stats[f"http_429.{rir}"] += 1
                if attempt == self.max_retries:
                    raise RdapRateLimited(url)
                await self._sleep(self._retry_after(resp, attempt))
                continue
            if resp.status_code == 404:
                self.stats["not_found"] += 1
                raise RdapNotFound(url)
            if resp.status_code >= 500:
                self.stats["errors"] += 1
                if attempt == self.max_retries:
                    raise RdapError(f"{resp.status_code} from {url}")
                await self._sleep(min(2**attempt, self.max_retry_after))
                continue
            if resp.status_code != 200:
                self.stats["errors"] += 1
                raise RdapError(f"{resp.status_code} from {url}")

            final_rir = rir_from_url(str(resp.url)) or rir
            if final_rir is None:
                raise RdapError(f"cannot determine RIR for {resp.url}")
            record = parse_rdap_network(resp.json(), final_rir)
            if not record.contains(addr):
                raise RdapError(f"RDAP network {record.start}-{record.end} does not contain {addr}")
            self.stats["ok"] += 1
            return RdapResult(record, str(resp.url), self._now())
        raise RdapError("unreachable")

    def _retry_after(self, resp: httpx.Response, attempt: int) -> float:
        header = resp.headers.get("Retry-After")
        if header:
            try:
                return min(float(header), self.max_retry_after)
            except ValueError:
                pass
        return min(2 ** (attempt + 1), self.max_retry_after)

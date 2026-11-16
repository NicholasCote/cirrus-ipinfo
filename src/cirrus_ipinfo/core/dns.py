"""PTR lookup with forward confirmation (FCrDNS), via the dedicated Unbound.

FCrDNS holds when the PTR name resolves (A for IPv4, AAAA for IPv6) back to
the original address. With several PTR records, the first one (sorted) that
forward-confirms wins; if none confirm, the first sorted name is reported
with ``fcrdns = False``, which keeps the result deterministic.

``timeout`` and ``servfail`` are *transient*. The enricher carries the
previous version's PTR forward instead of creating a new version for them.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from .addr import IPAddress

PtrStatus = Literal["ok", "nxdomain", "servfail", "timeout", "skipped"]
TRANSIENT: frozenset[str] = frozenset({"servfail", "timeout"})


@dataclass(frozen=True)
class DnsResult:
    ptr: str | None
    fcrdns: bool | None
    status: PtrStatus


class DnsBackend(Protocol):
    async def ptr(self, addr: IPAddress) -> list[str]: ...
    async def forward(self, name: str, version: int) -> list[str]: ...


class DnsPythonBackend:
    def __init__(self, nameservers: list[str], port: int = 53, timeout: float = 2.0):
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = nameservers
        r.port = port
        r.timeout = timeout
        r.lifetime = timeout
        self._r = r

    async def ptr(self, addr: IPAddress) -> list[str]:
        ans = await self._r.resolve(dns.reversename.from_address(str(addr)), "PTR")
        return [rr.target.to_text(omit_final_dot=True).lower() for rr in ans]

    async def forward(self, name: str, version: int) -> list[str]:
        try:
            ans = await self._r.resolve(name, "A" if version == 4 else "AAAA")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        return [rr.address for rr in ans]


class PtrResolver:
    def __init__(self, backend: DnsBackend, concurrency: int = 200):
        self._backend = backend
        self._sem = asyncio.Semaphore(concurrency)

    async def lookup(self, addr: IPAddress) -> DnsResult:
        async with self._sem:
            try:
                names = sorted(set(await self._backend.ptr(addr)))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return DnsResult(None, None, "nxdomain")
            except (dns.exception.Timeout, asyncio.TimeoutError):
                return DnsResult(None, None, "timeout")
            except (dns.resolver.NoNameservers, dns.exception.DNSException):
                return DnsResult(None, None, "servfail")
            if not names:
                return DnsResult(None, None, "nxdomain")
            for name in names:
                try:
                    fwd = await self._backend.forward(name, addr.version)
                except (dns.exception.DNSException, asyncio.TimeoutError):
                    continue
                if str(addr) in {str(type(addr)(a)) for a in fwd}:
                    return DnsResult(name, True, "ok")
            return DnsResult(names[0], False, "ok")

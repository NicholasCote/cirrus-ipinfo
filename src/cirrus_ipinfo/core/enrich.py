"""The enricher: one IP in, one :class:`EnrichmentRecord` out.

Shared by the nightly pipeline (``enrich_many`` over every IP seen that day)
and the API (on-demand single lookups, configured with no RDAP client so it
never spends registry budget or writes anything).

Order of evaluation:
1. Normalise (IPv4-mapped IPv6 → IPv4).
2. Special-purpose short-circuit: no lookups of any kind.
3. Local layers: routing, AS name, geo, classification, delegation.
4. Registry: dump → cache → RDAP (see ``registry.resolve``).
5. PTR + FCrDNS.
6. Transient PTR failures carry the previous version's PTR forward.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from .addr import IPAddress, normalize
from .dns import TRANSIENT, DnsResult, PtrResolver
from .hashing import changed_layers, content_hash, enricher_version
from .localdb import LocalData
from .model import EnrichmentRecord
from .provenance import SourceRef
from .registry.resolve import RegistryOutcome, RegistryResolver


@dataclass
class Candidate:
    """What ``load`` needs: the record plus its relation to the current version."""

    record: EnrichmentRecord
    content_hash: bytes
    changed_layers: tuple[str, ...]   # empty → unchanged, just bump last_verified_at

    @property
    def unchanged(self) -> bool:
        return not self.changed_layers


class Enricher:
    def __init__(
        self,
        local: LocalData,
        *,
        now: datetime,
        registry: RegistryResolver | None = None,
        dns: PtrResolver | None = None,
    ):
        self.local = local
        self.registry = registry
        self.dns = dns
        self.now = now
        self.version = enricher_version(local.categorizer.version)

    async def enrich(self, ip: str | IPAddress, prev: EnrichmentRecord | None = None) -> EnrichmentRecord:
        addr = normalize(ip)
        snapshot_ids = self.local.snapshot_ids()

        special = self.local.special.classify(addr)
        if special is not None:
            return self._categorize(EnrichmentRecord(
                ip=str(addr),
                registry_status="not_applicable",
                special_purpose=special,
                ptr_status="skipped",
                enricher_version=self.version,
                verified_at=self.now,
                snapshot_ids=snapshot_ids,
                sources={"classification": [s for s in self.local.sources_for("classification")
                                            if s.source == "iana_special"]},
            ))

        layers = self.local.local_layers(addr)
        route = layers.route
        routing_changed = prev is not None and (
            (prev.origin_asn, prev.announced_prefix) != (route.origin_asn if route else None,
                                                         route.prefix if route else None)
        )
        rir = layers.delegation.rir if layers.delegation else None

        if self.registry is not None:
            reg = await self.registry.resolve(
                addr, rir=rir, routing_changed=routing_changed,
                delegation_changed=layers.delegation_changed,
            )
        else:
            reg = RegistryOutcome("pending")

        dns_res = await self.dns.lookup(addr) if self.dns else DnsResult(None, None, "skipped")
        if dns_res.status in TRANSIENT and prev is not None and prev.ptr_status not in TRANSIENT:
            dns_res = DnsResult(prev.ptr, prev.fcrdns, prev.ptr_status)

        reg_sources = self.local.sources_for("registry")
        if reg.source == "rdap" and reg.fetched is not None:
            reg_sources = reg_sources + [SourceRef("rdap", reg.fetched.fetched_at.date())]

        cls = layers.classification
        return self._categorize(EnrichmentRecord(
            ip=str(addr),
            registry_status=reg.status,
            rir=(reg.network.rir if reg.network else rir),
            network=reg.network,
            origin_asn=route.origin_asn if route else None,
            origin_asns=route.origin_asns if route else (),
            as_name=layers.as_name,
            announced_prefix=route.prefix if route else None,
            geo_country=layers.geo.country,
            geo_country_name=layers.geo.country_name,
            geo_continent=layers.geo.continent,
            geo_region=layers.geo.region,
            geo_subdivisions=layers.geo.subdivisions,
            geo_city=layers.geo.city,
            geo_postal=layers.geo.postal,
            geo_timezone=layers.geo.timezone,
            geo_lat=layers.geo.latitude,
            geo_lon=layers.geo.longitude,
            geo_accuracy_km=layers.geo.accuracy_km,
            geo_source=layers.geo.source,
            ipinfo_asn=layers.asinfo.asn,
            ipinfo_as_name=layers.asinfo.as_name,
            as_domain=layers.asinfo.as_domain,
            ptr=dns_res.ptr,
            fcrdns=dns_res.fcrdns,
            ptr_status=dns_res.status,
            cloud_provider=cls.cloud_provider,
            cloud_region=cls.cloud_region,
            cloud_service=cls.cloud_service,
            tor_exit=cls.tor_exit,
            blocklists=cls.blocklists,
            enricher_version=self.version,
            verified_at=self.now,
            snapshot_ids=snapshot_ids,
            sources={
                "registry": reg_sources,
                "routing": self.local.sources_for("routing"),
                "geo": self.local.sources_for("geo"),
                "asinfo": self.local.sources_for("asinfo"),
                "classification": self.local.sources_for("classification"),
                "category": self.local.sources_for("category"),
            },
            registry_source=reg.source,
            registry_verified_at=reg.last_verified_at,
            registry_refetch_reasons=reg.refetch_reasons,
            registry_error=reg.error,
            rdap_fetch=reg.fetched,
            network_id=reg.network_id,
        ))

    def _categorize(self, rec: EnrichmentRecord) -> EnrichmentRecord:
        c = self.local.categorizer.categorize(rec)
        rec.category, rec.subcategory = c.category, c.subcategory
        rec.org_domain, rec.org_name = c.org_domain, c.org_name
        rec.category_basis, rec.legacy_category = c.basis, c.legacy
        return rec

    async def candidate(self, ip: str | IPAddress, prev: EnrichmentRecord | None = None) -> Candidate:
        rec = await self.enrich(ip, prev)
        return Candidate(rec, content_hash(rec), changed_layers(prev, rec))

    async def enrich_many(
        self,
        ips: Iterable[str],
        prev: Mapping[str, EnrichmentRecord] | None = None,
        concurrency: int = 64,
    ) -> list[Candidate]:
        prev = prev or {}
        sem = asyncio.Semaphore(concurrency)

        async def one(ip: str) -> Candidate:
            async with sem:
                key = str(normalize(ip))
                return await self.candidate(key, prev.get(key))

        return list(await asyncio.gather(*(one(ip) for ip in ips)))

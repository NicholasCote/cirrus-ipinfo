"""The enrichment record: one IP's state, flat like the ``ip_enrichment`` table.

Semantic fields (the ones that are hashed and versioned) are grouped into
*layers*. Provenance fields (when and from what) are carried alongside but
never hashed, so re-verifying identical data never creates a new version.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .provenance import SourceRef
from .registry.network import NetworkRecord
from .registry.rdap import RdapResult

# Layer → semantic fields. The registry layer is represented by the
# *content* of the network record (its hash), not by our row id.
LAYERS: dict[str, tuple[str, ...]] = {
    "registry": ("registry_status", "rir", "network_hash"),
    "routing": ("origin_asn", "origin_asns", "as_name", "announced_prefix"),
    "geo": ("geo_country", "geo_country_name", "geo_continent", "geo_region", "geo_subdivisions", "geo_city",
            "geo_postal", "geo_timezone", "geo_lat", "geo_lon", "geo_accuracy_km", "geo_source"),
    # IPinfo Lite's AS label (its own ASN, operator name and domain). Kept apart from routing,
    # whose origin ASN comes from the RouteViews RIB, so a relabel never looks like a route change.
    "asinfo": ("ipinfo_asn", "ipinfo_as_name", "as_domain"),
    "ptr": ("ptr", "fcrdns", "ptr_status"),
    "classification": ("special_purpose", "cloud_provider", "cloud_region", "cloud_service",
                       "tor_exit", "blocklists"),
    "category": ("category", "subcategory", "org_domain", "org_name", "category_basis",
                 "legacy_category"),
}


@dataclass
class EnrichmentRecord:
    ip: str
    # registry
    registry_status: str
    rir: str | None = None
    network: NetworkRecord | None = None
    network_hash: bytes | None = None  # derived from `network` when not given (DB rows supply it)
    # routing
    origin_asn: int | None = None
    origin_asns: tuple[int, ...] = ()
    as_name: str | None = None
    announced_prefix: str | None = None
    # geo
    geo_country: str | None = None
    geo_country_name: str | None = None
    geo_continent: str | None = None
    geo_region: str | None = None
    geo_subdivisions: tuple[str, ...] = ()
    geo_city: str | None = None
    geo_postal: str | None = None
    geo_timezone: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None
    geo_accuracy_km: int | None = None
    geo_source: str | None = None
    # IPinfo Lite AS label
    ipinfo_asn: int | None = None
    ipinfo_as_name: str | None = None
    as_domain: str | None = None
    # dns
    ptr: str | None = None
    fcrdns: bool | None = None
    ptr_status: str = "skipped"
    # classification
    special_purpose: str | None = None
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_service: str | None = None
    tor_exit: bool = False
    blocklists: tuple[str, ...] = ()
    # category (derived from the layers above by core.category)
    category: str | None = None
    subcategory: str | None = None
    org_domain: str | None = None
    org_name: str | None = None
    category_basis: str | None = None
    legacy_category: str | None = None
    # versioning / provenance (not hashed)
    enricher_version: str = ""
    verified_at: datetime | None = None
    snapshot_ids: tuple[int, ...] = ()
    sources: dict[str, list[SourceRef]] = field(default_factory=dict)
    registry_source: str | None = None           # ripe_dump | ... | rdap | cache
    registry_verified_at: datetime | None = None
    registry_refetch_reasons: tuple[str, ...] = ()
    registry_error: str | None = None
    rdap_fetch: RdapResult | None = None
    network_id: int | None = None

    def __post_init__(self) -> None:
        if self.network_hash is None and self.network is not None:
            self.network_hash = self.network.content_hash
        self.origin_asns = tuple(self.origin_asns)
        self.geo_subdivisions = tuple(self.geo_subdivisions)
        self.blocklists = tuple(sorted(self.blocklists))

    def layer_values(self, layer: str) -> dict:
        out = {}
        for name in LAYERS[layer]:
            v = getattr(self, name)
            if isinstance(v, bytes):
                v = v.hex()
            elif isinstance(v, tuple):
                v = list(v)
            out[name] = v
        return out

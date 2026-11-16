"""Local (bulk, offline) datasets and the bundle the enricher reads from.

MMDB layouts (from vendor documentation, 2026-11-13):

* IPinfo Lite (``ipinfo_lite.mmdb``, CC BY-SA 4.0, updated daily): flat
  records with ``asn`` (string, ``"AS13335"``), ``as_name``, ``as_domain``,
  ``country_code``, ``country``, ``continent_code``, ``continent``.
* DB-IP IP to City Lite (``dbip-city-lite-YYYY-MM.mmdb``, CC BY 4.0, updated
  monthly): GeoIP2-City-style records: ``country.iso_code``,
  ``subdivisions[].names.en``, ``city.names.en``, ``location.latitude/longitude``.

* MaxMind GeoLite2 City (``GeoLite2-City.mmdb``, GeoLite2 EULA, updated
  twice a week): the same layout plus ``postal.code``,
  ``location.time_zone`` and ``location.accuracy_radius``.

Geo rule: the country comes from IPinfo Lite (refreshed daily). Everything
below country level comes from GeoLite2, else DB-IP, *only if* that database
agrees on the country. Otherwise the datasets disagree about where the block
is, and showing a city from the other country would be wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import maxminddb

from .addr import IPAddress
from .category import Categorizer
from .classify import Classification, Classifier
from .provenance import SourceRef
from .rangeindex import DualRangeIndex
from .registry.delegated import DelegatedStats, Delegation
from .registry.network import NetworkRecord
from .registry.transfers import TransferLog
from .routing import AsNames, Route, RoutingTable
from .special import SpecialPurpose

__all__ = ["LocalData", "SourceRef", "IpinfoLiteReader", "DbipCityReader", "GeoLite2CityReader"]

IPINFO_ATTRIBUTION = "IP address data powered by IPinfo (https://ipinfo.io), CC BY-SA 4.0"
DBIP_ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
GEOLITE_ATTRIBUTION = "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com"


def _name(obj: dict | None) -> str | None:
    return ((obj or {}).get("names") or {}).get("en") or None


def _coord(v) -> float | None:
    return round(float(v), 4) if v is not None else None


class IpinfoLiteReader:
    def __init__(self, path: str | Path):
        self._db = maxminddb.open_database(str(path))

    def lookup(self, addr: IPAddress) -> dict | None:
        rec = self._db.get(str(addr))
        if not rec:
            return None
        asn = rec.get("asn")
        if isinstance(asn, str):
            asn = asn.upper().removeprefix("AS")
            asn = int(asn) if asn.isdigit() else None
        return {
            "country_code": rec.get("country_code") or None,
            "country": rec.get("country") or None,
            "continent_code": rec.get("continent_code") or None,
            "continent": rec.get("continent") or None,
            "asn": asn,
            "as_name": rec.get("as_name") or None,
            "as_domain": rec.get("as_domain") or None,
        }

    def close(self) -> None:
        self._db.close()


class _CityReader:
    """GeoIP2-City-style MMDB (MaxMind GeoLite2 City and DB-IP City Lite share the layout)."""

    def __init__(self, path: str | Path):
        self._db = maxminddb.open_database(str(path))

    def lookup(self, addr: IPAddress) -> dict | None:
        rec = self._db.get(str(addr))
        if not rec:
            return None
        loc = rec.get("location") or {}
        subs = tuple(n for n in (_name(s) for s in rec.get("subdivisions") or []) if n)
        country = rec.get("country") or {}
        return {
            "country_code": country.get("iso_code"),
            "country": _name(country),
            "continent_code": (rec.get("continent") or {}).get("code"),
            "subdivisions": subs,
            "region": subs[0] if subs else None,
            "city": _name(rec.get("city")),
            "postal": (rec.get("postal") or {}).get("code") or None,
            "timezone": loc.get("time_zone") or None,
            "latitude": _coord(loc.get("latitude")),
            "longitude": _coord(loc.get("longitude")),
            "accuracy_km": loc.get("accuracy_radius"),
        }

    def close(self) -> None:
        self._db.close()


class DbipCityReader(_CityReader):
    """DB-IP IP to City Lite: country, subdivisions, city, lat/lon (no postal code or time zone)."""


class GeoLite2CityReader(_CityReader):
    """MaxMind GeoLite2 City: adds postal code, time zone and accuracy radius."""


@dataclass(frozen=True)
class Geo:
    country: str | None = None              # ISO 3166-1 alpha-2
    country_name: str | None = None
    continent: str | None = None            # two-letter continent code
    region: str | None = None               # first-level subdivision (state, province)
    subdivisions: tuple[str, ...] = ()      # all levels, largest first
    city: str | None = None
    postal: str | None = None
    timezone: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_km: int | None = None
    source: str | None = None               # dataset the location below country level came from


@dataclass(frozen=True)
class AsInfo:
    """IPinfo Lite's view of the network: the AS, its operator name and web domain."""
    asn: int | None = None
    as_name: str | None = None
    as_domain: str | None = None


@dataclass(frozen=True)
class LocalLayers:
    route: Route | None
    as_name: str | None
    geo: Geo
    asinfo: AsInfo
    classification: Classification
    delegation: Delegation | None
    delegation_changed: bool


# Which dataset sources feed which output layer (for per-section provenance).
LAYER_SOURCES: dict[str, tuple[str, ...]] = {
    "routing": ("routeviews_pfx2as", "asnames"),
    "geo": ("ipinfo_lite", "geolite2_city", "dbip_city_lite"),
    "asinfo": ("ipinfo_lite",),
    "classification": ("aws", "gcp", "oracle", "cloudflare", "tor_exits",
                       "spamhaus_drop", "firehol_level1", "iana_special"),
    "category": ("public_suffix_list", "category_rules", "peeringdb"),
    "registry": ("delegated", "ripe_db", "apnic_db", "afrinic_db", "transfers", "iana_rdap_bootstrap"),
}


@dataclass
class LocalData:
    special: SpecialPurpose = field(default_factory=SpecialPurpose.default)
    routing: RoutingTable | None = None
    asnames: AsNames | None = None
    delegated: DelegatedStats | None = None
    previous_delegated: DelegatedStats | None = None
    registry_dumps: DualRangeIndex[NetworkRecord] | None = None
    classifier: Classifier | None = None
    transfers: TransferLog | None = None
    ipinfo: IpinfoLiteReader | None = None
    dbip: DbipCityReader | None = None
    geolite: GeoLite2CityReader | None = None
    categorizer: Categorizer = field(default_factory=Categorizer.default)
    snapshots: dict[str, SourceRef] = field(default_factory=dict)

    @staticmethod
    def build_registry_index(records) -> DualRangeIndex[NetworkRecord]:
        return DualRangeIndex.build(((r.start, r.end, r) for r in records), mode="most_specific")

    def snapshot_ids(self) -> tuple[int, ...]:
        return tuple(sorted({s.snapshot_id for s in self.snapshots.values() if s.snapshot_id is not None}))

    def sources_for(self, layer: str) -> list[SourceRef]:
        # Snapshot keys may carry a suffix per file (``cloudflare_v4``, ``delegated_arin``).
        wanted = LAYER_SOURCES.get(layer, ())
        return [ref for key, ref in sorted(self.snapshots.items())
                if any(key == w or key.startswith(w + "_") for w in wanted)]

    def geo(self, addr: IPAddress, ii: dict | None = None) -> Geo:
        """Country from IPinfo Lite (daily). Everything below country level comes from the first
        city database that agrees on the country: GeoLite2 City (postal code, time zone), then
        DB-IP City Lite. A city database that disagrees is placing the block in another country,
        so none of its detail is used."""
        cities = [(n, r.lookup(addr)) for n, r in (("geolite2_city", self.geolite), ("dbip_city_lite", self.dbip))
                  if r is not None]
        country = (ii or {}).get("country_code") or next((c["country_code"] for _, c in cities
                                                          if c and c.get("country_code")), None)
        name = (ii or {}).get("country") if (ii or {}).get("country_code") == country else None
        continent = (ii or {}).get("continent_code") if name else None
        for source, c in cities:
            if c and country and c.get("country_code") == country:
                return Geo(country, name or c.get("country"), continent or c.get("continent_code"), c["region"],
                           c["subdivisions"], c["city"], c["postal"], c["timezone"], c["latitude"],
                           c["longitude"], c["accuracy_km"], source)
        if name is None and country:
            name = next((c.get("country") for _, c in cities if c and c.get("country_code") == country), None)
        return Geo(country, name, continent)

    def delegation_changed(self, addr: IPAddress, current: Delegation | None) -> bool:
        if self.previous_delegated is None:
            return False
        prev = self.previous_delegated.lookup(addr)
        if prev is None or current is None:
            return (prev is None) != (current is None)
        return (prev.start, prev.end, prev.opaque_id, prev.status, prev.country) != (
            current.start, current.end, current.opaque_id, current.status, current.country)

    def local_layers(self, addr: IPAddress) -> LocalLayers:
        route = self.routing.lookup(addr) if self.routing else None
        as_name = self.asnames.get(route.origin_asn) if (self.asnames and route) else None
        deleg = self.delegated.lookup(addr) if self.delegated else None
        ii = self.ipinfo.lookup(addr) if self.ipinfo else None
        return LocalLayers(
            route=route,
            as_name=as_name,
            geo=self.geo(addr, ii),
            asinfo=AsInfo(ii.get("asn"), ii.get("as_name"), ii.get("as_domain")) if ii else AsInfo(),
            classification=self.classifier.classify(addr) if self.classifier else Classification(),
            delegation=deleg,
            delegation_changed=self.delegation_changed(addr, deleg),
        )

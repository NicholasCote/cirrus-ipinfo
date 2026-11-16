"""Postgres access for the pipeline (psycopg 3, sync; the writer role)."""

from __future__ import annotations

import ipaddress
import json
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date

import psycopg

from ..core.model import EnrichmentRecord
from ..core.registry.network import NetworkRecord
from ..core.registry.resolve import CachedNetwork, InMemoryNetworkCache


def connect(url: str, *, autocommit: bool = False) -> psycopg.Connection:
    url = url.replace("postgresql+psycopg://", "postgresql://", 1)
    return psycopg.connect(url, autocommit=autocommit, application_name="cirrus-ipinfo-pipeline")


# ----------------------------------------------------------- pipeline_run
@contextmanager
def run_record(url: str, day: date, stage: str, cluster: str | None = None):
    """Record a stage in ``pipeline_run`` on its own autocommit connection, so the
    row survives a rolled-back stage transaction. Yields a dict for stats and
    snapshot ids."""
    info: dict = {"stats": {}, "snapshot_ids": []}
    with connect(url, autocommit=True) as conn:
        run_id = conn.execute("INSERT INTO ipinfo.pipeline_run (run_date, stage, cluster) VALUES (%s, %s, %s) "
                              "RETURNING id", (day, stage, cluster)).fetchone()[0]
        try:
            yield info
        except BaseException as exc:
            conn.execute("UPDATE ipinfo.pipeline_run SET status = 'failed', finished_at = now(), stats = %s, "
                         "snapshot_ids = %s, error = %s WHERE id = %s",
                         (json.dumps(info["stats"], default=str), list(info["snapshot_ids"]),
                          f"{type(exc).__name__}: {exc}"[:4000], run_id))
            raise
        conn.execute("UPDATE ipinfo.pipeline_run SET status = 'succeeded', finished_at = now(), stats = %s, "
                     "snapshot_ids = %s WHERE id = %s",
                     (json.dumps(info["stats"], default=str), list(info["snapshot_ids"]), run_id))


# ----------------------------------------------------------- network cache
_NET_COLS = """n.id, host(lower(n.range)), host(upper(n.range)), n.rir, n.source, n.handle, n.parent_handle,
               n.status, n.org_handle, n.org, n.netname, n.country, n.abuse_contact, n.registered_at,
               n.rir_last_changed, n.last_verified_at"""


def _network(row) -> tuple[int, NetworkRecord]:
    (nid, lo, hi, rir, source, handle, parent, status, org_handle, org, netname, country, abuse,
     registered, changed) = row[:15]
    return nid, NetworkRecord(ipaddress.ip_address(lo), ipaddress.ip_address(hi), rir, source, handle, parent,
                              status, org_handle, org, netname, country, abuse, registered, changed)


async def load_network_cache(conn: psycopg.Connection) -> InMemoryNetworkCache:
    """All current network rows → in-memory cache.

    ``network`` holds only ranges that covered an observed IP, so it stays
    small enough to load whole; the resolver then needs no per-IP queries.
    """
    cache = InMemoryNetworkCache()
    for row in conn.execute(f"SELECT {_NET_COLS} FROM ipinfo.network n WHERE n.superseded_at IS NULL"):
        nid, rec = _network(row)
        await cache.put(CachedNetwork(rec, row[15], nid))
    return cache


# ----------------------------------------------------- current enrichment
@dataclass
class CurrentVersion:
    id: int
    valid_from: date
    record: EnrichmentRecord


def load_current(conn: psycopg.Connection, ips: list[str]) -> dict[str, CurrentVersion]:
    out: dict[str, CurrentVersion] = {}
    sql = """SELECT e.id, e.valid_from, host(e.ip), e.registry_status, e.rir, n.content_hash,
                    e.origin_asn, e.origin_asns, e.as_name, e.announced_prefix::text,
                    e.geo_country, e.geo_region, e.geo_city, e.ptr, e.fcrdns, e.ptr_status,
                    e.special_purpose, e.cloud_provider, e.cloud_region, e.cloud_service, e.tor_exit, e.blocklists,
                    e.category, e.subcategory, e.org_domain, e.org_name, e.category_basis, e.legacy_category,
                    e.enricher_version, e.network_id, e.snapshot_ids,
                    e.geo_country_name, e.geo_continent, e.geo_subdivisions, e.geo_postal, e.geo_timezone,
                    e.geo_lat, e.geo_lon, e.geo_accuracy_km, e.geo_source, e.ipinfo_asn, e.ipinfo_as_name,
                    e.as_domain
             FROM ipinfo.ip_enrichment e LEFT JOIN ipinfo.network n ON n.id = e.network_id
             WHERE e.superseded_at IS NULL AND e.ip = ANY(%s::inet[])"""
    for i in range(0, len(ips), 5000):
        for r in conn.execute(sql, (ips[i:i + 5000],)):
            rec = EnrichmentRecord(
                ip=r[2], registry_status=r[3], rir=r[4], network_hash=bytes(r[5]) if r[5] else None,
                origin_asn=r[6], origin_asns=tuple(r[7] or ()), as_name=r[8], announced_prefix=r[9],
                geo_country=r[10], geo_region=r[11], geo_city=r[12], ptr=r[13], fcrdns=r[14], ptr_status=r[15],
                special_purpose=r[16], cloud_provider=r[17], cloud_region=r[18], cloud_service=r[19],
                tor_exit=r[20], blocklists=tuple(r[21] or ()), category=r[22], subcategory=r[23],
                org_domain=r[24], org_name=r[25], category_basis=r[26], legacy_category=r[27],
                enricher_version=r[28], network_id=r[29], snapshot_ids=tuple(r[30] or ()),
                geo_country_name=r[31], geo_continent=r[32], geo_subdivisions=tuple(r[33] or ()),
                geo_postal=r[34], geo_timezone=r[35], geo_lat=r[36], geo_lon=r[37], geo_accuracy_km=r[38],
                geo_source=r[39], ipinfo_asn=r[40], ipinfo_as_name=r[41], as_domain=r[42])
            out[r[2]] = CurrentVersion(r[0], r[1], rec)
    return out

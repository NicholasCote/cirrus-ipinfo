"""Read-only HTTP API (FastAPI): "what do we know about this IP?"

    GET  /                       small lookup page
    GET  /docs                   OpenAPI / Swagger UI
    GET  /v1/ip/{ip}             any IP: the stored current version, else computed on demand
    GET  /v1/ip/{ip}/history     every stored version (point-in-time record)
    POST /v1/ip/batch            up to 1000 IPs → NDJSON, one line per IP, in request order
    POST /v1/submit              queue up to 10000 IPs for full enrichment by the nightly run
    GET  /v1/summary             category → subcategory → organisation counts over recent days
    GET  /healthz, /readyz

Stored IPs come from the database (``stored: true``). Any other IP is enriched on
demand from the local datasets and a live PTR lookup, without RDAP and without
writing anything (``stored: false``); ``submit`` queues it so the nightly run
stores a full, versioned record. Every record carries a ``gdex`` block: the
``dssdb.ipinfo`` row GDEX metrics stores today (see ``core.gdex``);
``view=gdex`` returns only that block.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from decimal import Decimal
from importlib import resources
from typing import Annotated, Any, Literal

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .. import __version__
from ..core import gdex
from ..core.addr import normalize
from ..core.localdb import DBIP_ATTRIBUTION, GEOLITE_ATTRIBUTION, IPINFO_ATTRIBUTION
from ..core.model import EnrichmentRecord
from ..core.special import SpecialPurpose
from .ondemand import OnDemand

MAX_BATCH = 1000
MAX_SUBMIT = 10000
# A stored IP is re-queued by a submission once its current version is this old.
RESUBMIT_AFTER_DAYS = 90
SOURCE_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")
View = Literal["full", "gdex"]
NONE = "(none)"
# Organisation shown for an observation: its registered domain, else the registry/AS org name.
ORG_EXPR = "coalesce(o.org_domain, e.org_name, '(unknown)')"
SPECIAL = SpecialPurpose.default()

_ENRICH = """
SELECT host(e.ip) AS ip, e.id AS version_id, e.valid_from, e.superseded_at,
       e.first_verified_at, e.last_verified_at, e.enricher_version, e.changed_layers, e.snapshot_ids,
       e.category, e.subcategory, e.org_domain, e.org_name, e.category_basis, e.legacy_category,
       e.registry_status, e.rir, e.origin_asn, e.origin_asns, e.as_name, e.announced_prefix,
       e.geo_country, e.geo_region, e.geo_city, e.ptr, e.fcrdns, e.ptr_status,
       e.geo_country_name, e.geo_continent, e.geo_subdivisions, e.geo_postal, e.geo_timezone, e.geo_lat,
       e.geo_lon, e.geo_accuracy_km, e.geo_source, e.ipinfo_asn, e.ipinfo_as_name, e.as_domain,
       e.cloud_provider, e.cloud_region, e.cloud_service, e.tor_exit, e.blocklists, e.special_purpose,
       n.id AS network_id, host(lower(n.range)) AS net_start, host(upper(n.range)) AS net_end, n.cidrs AS net_cidrs,
       n.rir AS net_rir, n.source AS net_source, n.handle AS net_handle, n.parent_handle AS net_parent_handle,
       n.status AS net_status, n.org_handle AS net_org_handle, n.org AS net_org, n.netname AS net_netname,
       n.country AS net_country, n.abuse_contact AS net_abuse_contact, n.registered_at AS net_registered_at,
       n.rir_last_changed AS net_rir_last_changed, n.fetched_at AS net_fetched_at,
       n.last_verified_at AS net_last_verified_at
FROM ipinfo.ip_enrichment e LEFT JOIN ipinfo.network n ON n.id = e.network_id
"""


ATTRIBUTION = [IPINFO_ATTRIBUTION, GEOLITE_ATTRIBUTION, DBIP_ATTRIBUTION]


def _plain(v: Any) -> Any:
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network,
                      ipaddress.IPv6Network, ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return int(v)
    if isinstance(v, (bytes, memoryview)):
        return bytes(v).hex()
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v


_GEO = {"country": "geo_country", "country_name": "geo_country_name", "continent": "geo_continent",
        "region": "geo_region", "subdivisions": "geo_subdivisions", "city": "geo_city", "postal": "geo_postal",
        "timezone": "geo_timezone", "latitude": "geo_lat", "longitude": "geo_lon",
        "accuracy_radius_km": "geo_accuracy_km", "source": "geo_source"}
_RECORD_FIELDS = ("ip", "registry_status", "rir", "origin_asn", "as_name", "announced_prefix", "geo_country",
                  "geo_country_name", "geo_continent", "geo_region", "geo_city", "geo_postal", "geo_timezone",
                  "geo_lat", "geo_lon", "geo_accuracy_km", "geo_source", "ptr", "fcrdns", "ptr_status",
                  "cloud_provider", "cloud_region", "cloud_service", "tor_exit", "special_purpose", "category",
                  "subcategory", "org_domain", "org_name", "category_basis", "legacy_category", "ipinfo_asn",
                  "ipinfo_as_name", "as_domain")


def _record_of(row: dict) -> EnrichmentRecord:
    """The fields of a stored row that ``core.gdex`` reads."""
    return EnrichmentRecord(**{k: row.get(k) for k in _RECORD_FIELDS},
                            origin_asns=tuple(row.get("origin_asns") or ()),
                            geo_subdivisions=tuple(row.get("geo_subdivisions") or ()),
                            blocklists=tuple(row.get("blocklists") or ()))


def _row_of(rec: EnrichmentRecord) -> dict:
    """An on-demand record in the shape of an ``_ENRICH`` row."""
    row: dict[str, Any] = {k: getattr(rec, k) for k in _RECORD_FIELDS}
    row.update(origin_asns=list(rec.origin_asns) or None, geo_subdivisions=list(rec.geo_subdivisions),
               blocklists=list(rec.blocklists), version_id=None, valid_from=None, superseded_at=None,
               first_verified_at=None, last_verified_at=None, enricher_version=rec.enricher_version,
               changed_layers=None, snapshot_ids=list(rec.snapshot_ids), network_id=None)
    n = rec.network
    if n is not None:
        row.update(network_id=rec.network_id, net_start=str(n.start), net_end=str(n.end), net_cidrs=n.cidrs,
                   net_rir=n.rir, net_source=n.source, net_handle=n.handle, net_parent_handle=n.parent_handle,
                   net_status=n.status, net_org_handle=n.org_handle, net_org=n.org, net_netname=n.netname,
                   net_country=n.country, net_abuse_contact=n.abuse_contact, net_registered_at=n.registered_at,
                   net_rir_last_changed=n.rir_last_changed, net_fetched_at=None,
                   net_last_verified_at=rec.registry_verified_at)
        if row["network_id"] is None:
            row["network_id"] = 0          # from the registry cache/dumps, not a stored row id
    return row


def _shape(row: dict, sources: list[dict] | None = None, seen: dict | None = None, *, stored: bool = True) -> dict:
    gdex_block = gdex.record(_record_of(row), stored=stored)
    r = {k: _plain(v) for k, v in row.items()}
    net = None
    if r.get("network_id") is not None:
        net = {k[4:]: r[k] for k in list(r) if k.startswith("net_")}
        net["id"] = r["network_id"] or None
    out = {
        "ip": r["ip"],
        "stored": stored,
        "category": {k: r[k] for k in ("category", "subcategory", "org_domain", "org_name", "category_basis",
                                        "legacy_category")},
        "registry": {"status": r["registry_status"], "rir": r["rir"], "network": net},
        "routing": {k: r[k] for k in ("origin_asn", "origin_asns", "as_name", "announced_prefix")},
        "asinfo": {"asn": r["ipinfo_asn"], "as_name": r["ipinfo_as_name"], "as_domain": r["as_domain"]},
        "geo": {k: r[col] for k, col in _GEO.items()},
        "dns": {"ptr": r["ptr"], "fcrdns": r["fcrdns"], "status": r["ptr_status"]},
        "classification": {k: r[k] for k in ("special_purpose", "cloud_provider", "cloud_region", "cloud_service",
                                              "tor_exit", "blocklists")},
        "version": ({k: r[k] for k in ("version_id", "valid_from", "superseded_at", "first_verified_at",
                                        "last_verified_at", "enricher_version", "changed_layers")}
                    if stored else None),
        "gdex": gdex_block,
    }
    if sources is not None:
        out["sources"] = sources
    if seen is not None:
        out["seen"] = seen
    out["attribution"] = ATTRIBUTION
    return out


def _ip_or_400(ip: str) -> str:
    try:
        return str(normalize(ip))
    except ValueError:
        raise HTTPException(400, f"not an IP address: {ip!r}") from None


def create_app(database_url: str | None = None, ondemand: OnDemand | None = None) -> FastAPI:
    """``ondemand``: the on-demand engine. Default: load datasets from the S3 snapshots
    (needs the S3_* settings); pass ``OnDemand(loaded=...)`` in tests."""
    url = (database_url or os.environ.get("IPINFO_DATABASE_URL", "")).replace("postgresql+psycopg://",
                                                                              "postgresql://", 1)
    pool = AsyncConnectionPool(url, min_size=1, max_size=10, open=False,
                               kwargs={"row_factory": dict_row, "application_name": "cirrus-ipinfo-api"})
    if ondemand is None:
        from ..pipeline.config import Settings
        settings = Settings()
        settings.database_url = url
        ondemand = OnDemand(settings=settings)
    od = ondemand

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await pool.open()
        od.start()
        yield
        await od.stop()
        await pool.close()

    app = FastAPI(
        title="CIRRUS IP info",
        version=__version__,
        lifespan=lifespan,
        description="What CIRRUS knows about client IP addresses: registry ownership, routing, geo, reverse DNS, "
                    "cloud/Tor/blocklist classification and research categories, with point-in-time history. "
                    "Any IP can be looked up: stored IPs come from the database, others are computed on demand "
                    "(`stored: false`) and can be submitted for full enrichment by the nightly run. "
                    "Every record has a `gdex` block in the shape of GDEX metrics' `dssdb.ipinfo` row; "
                    "`view=gdex` returns only that block. "
                    + " ".join(f"{a}." for a in ATTRIBUTION),
    )

    async def _sources(conn, ids: list[int]) -> list[dict]:
        if not ids:
            return []
        cur = await conn.execute("SELECT source, snapshot_date, license, attribution FROM ipinfo.dataset_snapshot "
                                 "WHERE id = ANY(%s) ORDER BY source", (ids,))
        return [{k: _plain(v) for k, v in r.items()} for r in await cur.fetchall()]

    async def _seen(conn, ip: str) -> dict:
        cur = await conn.execute(
            """SELECT min(day) AS first_day, max(day) AS last_day, count(DISTINCT day) AS days, sum(hits) AS requests,
                      array_agg(DISTINCT cluster) AS clusters, array_agg(DISTINCT tenant) AS tenants,
                      array_agg(DISTINCT host) AS hosts
               FROM ipinfo.observation WHERE ip = %s::inet""", (ip,))
        return {k: _plain(v) for k, v in (await cur.fetchone()).items()}

    async def _current(conn, ips: list[str]) -> dict[str, dict]:
        cur = await conn.execute(_ENRICH + " WHERE e.superseded_at IS NULL AND e.ip = ANY(%s::inet[])", (ips,))
        return {r["ip"]: r for r in await cur.fetchall()}

    async def _queue(conn, ips: list[str], source: str | None, stored: dict[str, dict]) -> set[str]:
        """Queue IPs for the nightly run: unstored ones, and stored ones whose current version is
        older than RESUBMIT_AFTER_DAYS. Special-purpose addresses are never queued."""
        cutoff = datetime.now().astimezone() - timedelta(days=RESUBMIT_AFTER_DAYS)
        want = sorted({ip for ip in ips if not SPECIAL.classify(normalize(ip))
                       and (ip not in stored or stored[ip]["last_verified_at"] < cutoff)})
        if not want:
            return set()
        await conn.execute(
            """INSERT INTO ipinfo.submission (ip, sources)
               SELECT unnest(%s::inet[]), %s::text[]
               ON CONFLICT (ip) DO UPDATE SET
                 last_submitted_at = now(), submit_count = submission.submit_count + 1,
                 sources = ARRAY(SELECT DISTINCT unnest(submission.sources || EXCLUDED.sources) ORDER BY 1),
                 processed_at = NULL, attempts = CASE WHEN submission.processed_at IS NULL
                                                      THEN submission.attempts ELSE 0 END""",
            (want, [source] if source else []))
        await conn.commit()
        return set(want)

    def _check_source(source: str | None) -> None:
        if source is not None and not SOURCE_RE.match(source):
            raise HTTPException(422, "source: 1-64 characters of a-z, 0-9, '_', '.', '-'")

    def _unavailable(ip: str) -> dict:
        return {"ip": ip, "stored": False,
                "error": "not stored, and on-demand lookups are unavailable while datasets load"
                         + (f" ({od.error})" if od.error else "")}

    def _not_found(ip: str) -> HTTPException:
        detail = {"ip": ip, "stored": False, "message": "No stored versions of this IP."}
        if special := SPECIAL.classify(normalize(ip)):
            detail["special_purpose"] = special
        return HTTPException(404, detail)

    def _view(out: dict, view: View) -> dict:
        return out["gdex"] if view == "gdex" and "gdex" in out else out

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")
        return {"ok": True}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> dict:
        """Ready once the database answers and the on-demand datasets are loaded."""
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")
        if not od.ready:
            raise HTTPException(503, {"ok": False, "datasets": "loading", "error": od.error})
        return {"ok": True, "datasets": od.loaded.snapshot_marker if od.loaded else None}

    @app.get("/v1/ip/{ip}", summary="Any IP: the stored current version, else computed on demand")
    async def get_ip(ip: str, view: View = "full",
                     submit: Annotated[bool, Query(description="Queue for full enrichment by the nightly run "
                                                               "if not stored (or stored > 90 days ago)")] = False,
                     source: Annotated[str | None, Query(description="Who is submitting, e.g. gdex")] = None,
                     ) -> dict:
        ip = _ip_or_400(ip)
        _check_source(source)
        async with pool.connection() as conn:
            rows = await _current(conn, [ip])
            queued = await _queue(conn, [ip], source, rows) if submit else set()
            if ip in rows:
                row = rows[ip]
                out = _shape(row, await _sources(conn, row["snapshot_ids"] or []), await _seen(conn, ip))
            else:
                out = None
        if out is None:
            if not od.ready:
                raise HTTPException(503, _unavailable(ip))
            out = _shape(_row_of(await od.enrich(ip)), stored=False)
        if submit:
            out["queued"] = ip in queued
        return _view(out, view)

    @app.get("/v1/ip/{ip}/history", summary="Every stored version of one IP, oldest first")
    async def get_history(ip: str) -> dict:
        ip = _ip_or_400(ip)
        async with pool.connection() as conn:
            cur = await conn.execute(_ENRICH + " WHERE e.ip = %s::inet ORDER BY e.valid_from", (ip,))
            rows = await cur.fetchall()
        if not rows:
            raise _not_found(ip)
        return {"ip": ip, "versions": [_shape(r) for r in rows]}

    @app.post("/v1/ip/batch", summary=f"Up to {MAX_BATCH} IPs; NDJSON response, one line per IP in request order")
    async def batch(ips: Annotated[list[str], Body(max_length=MAX_BATCH)],
                    submit: Annotated[bool, Body(description="Queue unstored IPs for the nightly run")] = False,
                    source: Annotated[str | None, Body(description="Who is submitting, e.g. gdex")] = None,
                    view: View = "full") -> StreamingResponse:
        _check_source(source)
        norm: list[tuple[str, str | None]] = []
        for raw in ips:
            try:
                norm.append((raw, str(normalize(raw))))
            except ValueError:
                norm.append((raw, None))
        valid = sorted({ip for _, ip in norm if ip})
        async with pool.connection() as conn:
            rows = await _current(conn, valid)
            queued = await _queue(conn, valid, source, rows) if submit else set()
        enricher = od.enricher() if od.ready else None
        tasks: dict[str, asyncio.Task] = {}
        if enricher is not None:
            tasks = {ip: asyncio.create_task(od.enrich(ip, enricher)) for ip in valid if ip not in rows}

        async def one(raw: str, ip: str | None) -> dict:
            if ip is None:
                return {"ip": raw, "error": "not an IP address"}
            if ip in rows:
                out = _shape(rows[ip])
            elif ip in tasks:
                try:
                    out = _shape(_row_of(await tasks[ip]), stored=False)
                except Exception as exc:
                    return {"ip": ip, "stored": False, "error": f"{type(exc).__name__}: {exc}"}
            else:
                return _unavailable(ip)
            if submit:
                out["queued"] = ip in queued
            return _view(out, view)

        async def gen():
            try:
                for raw, ip in norm:
                    yield json.dumps(await one(raw, ip)) + "\n"
            finally:
                for t in tasks.values():
                    t.cancel()
        return StreamingResponse(gen(), media_type="application/x-ndjson")

    @app.post("/v1/submit", summary=f"Queue up to {MAX_SUBMIT} IPs for full enrichment by the nightly run",
              status_code=202)
    async def submit_ips(ips: Annotated[list[str], Body(max_length=MAX_SUBMIT)],
                         source: Annotated[str | None, Body(description="Who is submitting, e.g. gdex")] = None,
                         ) -> dict:
        _check_source(source)
        valid, invalid = set(), []
        for raw in ips:
            try:
                valid.add(str(normalize(raw)))
            except ValueError:
                invalid.append(raw)
        special = {ip for ip in valid if SPECIAL.classify(normalize(ip))}
        async with pool.connection() as conn:
            rows = await _current(conn, sorted(valid))
            queued = await _queue(conn, sorted(valid), source, rows)
        return {"received": len(ips), "queued": len(queued), "special_purpose": len(special),
                "already_stored": sum(1 for ip in valid if ip in rows and ip not in queued and ip not in special),
                "invalid": invalid[:100],
                "invalid_count": len(invalid)}

    @app.get("/v1/summary", summary="Category / subcategory / organisation breakdown of observed traffic")
    async def summary(days: Annotated[int, Query(ge=1, le=400)] = 7, cluster: str | None = None,
                      tenant: str | None = None, category: str | None = None,
                      top: Annotated[int, Query(ge=1, le=500)] = 25) -> dict:
        where = ["o.day > (SELECT max(day) FROM ipinfo.observation) - %s"]
        args: list[Any] = [days]
        for col, val in (("cluster", cluster), ("tenant", tenant), ("category", category)):
            if val:
                where.append(f"o.{col} = %s")
                args.append(val)
        w = " AND ".join(where)
        async with pool.connection() as conn:
            cats = await (await conn.execute(
                f"""SELECT o.category, o.subcategory, count(DISTINCT o.ip) AS ips, sum(o.hits) AS requests
                    FROM ipinfo.observation o WHERE {w} GROUP BY 1, 2 ORDER BY requests DESC""", args)).fetchall()
            orgs = await (await conn.execute(
                f"""SELECT o.category, coalesce(o.org_domain, e.org_name) AS organisation,
                           count(DISTINCT o.ip) AS ips, sum(o.hits) AS requests
                    FROM ipinfo.observation o JOIN ipinfo.ip_enrichment e ON e.id = o.enrichment_id
                    WHERE {w} GROUP BY 1, 2 ORDER BY requests DESC LIMIT %s""", [*args, top])).fetchall()
            span = await (await conn.execute(
                f"SELECT min(o.day) AS first_day, max(o.day) AS last_day FROM ipinfo.observation o WHERE {w}",
                args)).fetchone()
        plain = lambda rows: [{k: _plain(v) for k, v in r.items()} for r in rows]  # noqa: E731
        return {**{k: _plain(v) for k, v in span.items()}, "categories": plain(cats), "top_organisations": plain(orgs)}

    def _filters(days: int, cluster: str | None, tenant: str | None, namespace: str | None, host: str | None,
                 category: str | None = None, subcategory: str | None = None,
                 organisation: str | None = None, ingress: str | None = None) -> tuple[str, list[Any]]:
        where = ["o.day > (SELECT max(day) FROM ipinfo.observation) - %s"]
        args: list[Any] = [days]
        for col, val in (("o.cluster", cluster), ("o.tenant", tenant), ("o.namespace", namespace),
                         ("o.host", host), ("o.category", category)):
            if val:
                where.append(f"{col} = %s")
                args.append(val)
        if ingress:     # comma-separated: "traefik-external,traefik-internal"
            where.append("o.ingress = ANY(%s)")
            args.append([x.strip() for x in ingress.split(",") if x.strip()])
        if subcategory:
            where.append("coalesce(o.subcategory, '') = %s")
            args.append("" if subcategory == NONE else subcategory)
        if organisation:
            where.append(f"{ORG_EXPR} = %s")
            args.append(organisation)
        return " AND ".join(where), args

    @app.get("/v1/breakdown", summary="Traffic split one level down: category → subcategory → organisation → ip")
    async def breakdown(
        level: Annotated[str, Query(pattern="^(category|subcategory|organisation|ip)$")] = "category",
        days: Annotated[int, Query(ge=1, le=400)] = 7,
        cluster: str | None = None, tenant: str | None = None, namespace: str | None = None,
        host: str | None = None, category: str | None = None, subcategory: str | None = None,
        organisation: str | None = None, ingress: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> dict:
        """Each row: ``key`` (pass it back as the filter for the next level), ``ips``, ``requests``.
        Rows are ordered by requests; ``total`` covers every row, not just the returned ones."""
        key = {"category": "o.category", "subcategory": f"coalesce(o.subcategory, '{NONE}')",
               "organisation": ORG_EXPR, "ip": "host(o.ip)"}[level]
        w, args = _filters(days, cluster, tenant, namespace, host, category, subcategory, organisation, ingress)
        sql = f"""SELECT {key} AS key, count(DISTINCT o.ip) AS ips, sum(o.hits) AS requests
                  FROM ipinfo.observation o JOIN ipinfo.ip_enrichment e ON e.id = o.enrichment_id
                  WHERE {w} GROUP BY 1 ORDER BY requests DESC, key"""
        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, args)).fetchall()
            tot = await (await conn.execute(
                f"""SELECT count(DISTINCT o.ip) AS ips, coalesce(sum(o.hits), 0) AS requests,
                           min(o.day) AS first_day, max(o.day) AS last_day
                    FROM ipinfo.observation o JOIN ipinfo.ip_enrichment e ON e.id = o.enrichment_id
                    WHERE {w}""", args)).fetchone()
        return {"level": level, **{k: _plain(v) for k, v in tot.items()},
                "rows": [{k: _plain(v) for k, v in r.items()} for r in rows[:limit]],
                "truncated": len(rows) > limit}

    @app.get("/v1/applications", summary="Namespaces and the hosts (applications) under each, by traffic")
    async def applications(days: Annotated[int, Query(ge=1, le=400)] = 30, cluster: str | None = None,
                           ingress: str | None = None) -> dict:
        """Each namespace lists its hosts and, per ingress controller, its request count — so
        namespaces still served through ingress-nginx stand out."""
        w, args = _filters(days, cluster, None, None, None, ingress=ingress)
        async with pool.connection() as conn:
            rows = await (await conn.execute(
                f"""SELECT o.namespace, o.tenant, o.host, o.ingress, sum(o.hits) AS requests,
                           count(DISTINCT o.ip) AS ips
                    FROM ipinfo.observation o WHERE {w} GROUP BY 1, 2, 3, 4 ORDER BY 1, 5 DESC""", args)).fetchall()
            ingresses = await (await conn.execute(
                f"""SELECT o.ingress, sum(o.hits) AS requests, count(DISTINCT o.ip) AS ips,
                           count(DISTINCT o.namespace) AS namespaces
                    FROM ipinfo.observation o WHERE {w} GROUP BY 1 ORDER BY 2 DESC""", args)).fetchall()
            clusters = await (await conn.execute(
                f"""SELECT o.cluster, sum(o.hits) AS requests, count(DISTINCT o.ip) AS ips
                    FROM ipinfo.observation o WHERE {w} GROUP BY 1 ORDER BY 1""", args)).fetchall()
        out: dict[str, dict] = {}
        for r in rows:
            ns = out.setdefault(r["namespace"], {"namespace": r["namespace"], "tenant": r["tenant"],
                                                 "requests": 0, "ingress": {}, "hosts": {}})
            ns["requests"] += int(r["requests"])
            ns["ingress"][r["ingress"]] = ns["ingress"].get(r["ingress"], 0) + int(r["requests"])
            h = ns["hosts"].setdefault(r["host"], {"host": r["host"], "requests": 0, "ips": 0, "ingress": []})
            h["requests"] += int(r["requests"])
            h["ips"] = max(h["ips"], r["ips"])
            h["ingress"].append(r["ingress"])
        for ns in out.values():
            ns["hosts"] = sorted(ns["hosts"].values(), key=lambda h: -h["requests"])
        return {"ingresses": [{k: _plain(v) for k, v in r.items()} for r in ingresses],
                "clusters": [{k: _plain(v) for k, v in r.items()} for r in clusters],
                "namespaces": sorted(out.values(), key=lambda n: -n["requests"])}

    app.mount("/static", StaticFiles(directory=str(resources.files("cirrus_ipinfo") / "api" / "static")),
              name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(str(resources.files("cirrus_ipinfo") / "api" / "static" / "favicon.ico"))

    @app.get("/", include_in_schema=False, response_class=HTMLResponse)
    async def index() -> str:
        return (resources.files("cirrus_ipinfo") / "api" / "index.html").read_text()

    return app


app = create_app()

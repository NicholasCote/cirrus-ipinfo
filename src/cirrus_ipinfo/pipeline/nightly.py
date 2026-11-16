"""The nightly run on mlc1, stage by stage. Each stage is recorded in ``pipeline_run``.

    maintain      ensure observation partitions (so load can't miss one)
    refresh       datasets → S3 snapshots → dataset_snapshot
    sync_tenants  this cluster's namespace → tenant map → S3
    collect       per cluster: Loki (via Grafana) → collected/day=D/cluster=C/
    enrich        distinct IPs → EnrichmentRecords (RDAP + PTR live) → enrich/day=D/
    load          one transaction: networks, versions, observations
    maintain      drop partitions past retention

nwc1 only runs ``sync-tenants``; its logs are read from the shared Loki here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta

import dns.resolver
import httpx

from ..core.dns import DnsPythonBackend, PtrResolver
from ..core.enrich import Enricher
from ..core.registry.rdap import RdapClient
from ..core.registry.resolve import RegistryResolver
from . import collect as collect_mod
from . import submissions as submissions_mod
from . import tenants as tenants_mod
from .config import Settings
from .datasets import load_local, refresh
from .db import connect, load_current, load_network_cache, run_record
from .load import drop_categories, load
from .loki import GrafanaLoki, LogSource
from .store import Store, dump_jsonl_gz, load_jsonl_gz, open_store

log = logging.getLogger(__name__)


def yesterday() -> date:
    return (datetime.now(UTC) - timedelta(days=1)).date()


def _db_url(s: Settings) -> str:
    if not s.database_url:
        raise RuntimeError("IPINFO_DATABASE_URL is not set")
    return s.database_url


# ------------------------------------------------------------------ stages
def stage_sync_tenants(s: Settings, store: Store, day: date | None = None) -> dict:
    ns = tenants_mod.list_namespaces()
    uri = store.put(tenants_mod.key(s.cluster), tenants_mod.document(s.cluster, ns))
    stats = {"namespaces": len(ns), "with_tenant": sum(1 for t in ns.values() if t), "s3_uri": uri}
    log.info("sync-tenants %s: %s", s.cluster, stats)
    if day is not None and s.database_url:
        with run_record(s.database_url, day, "sync_tenants", s.cluster) as run:
            run["stats"] = stats
    return stats


async def stage_collect(s: Settings, store: Store, day: date, cluster: str) -> list[dict]:
    if not s.loki_datasource_uid:
        raise RuntimeError("LOKI_DATASOURCE_UID is not set")
    tmap = tenants_mod.TenantMap.from_document(store.get(tenants_mod.key(cluster)))
    with run_record(_db_url(s), day, "collect", cluster) as run:
        async with httpx.AsyncClient(timeout=120) as http:
            loki = GrafanaLoki(http, s.grafana_url, s.loki_datasource_uid, s.grafana_token)
            res = await collect_mod.collect(loki, [LogSource.from_dict(d) for d in s.log_sources], day, cluster,
                                          tmap, store, s.exclude_cidrs.get(cluster, ()))
        run["stats"] = {**res.stats, "loki": loki.stats, "tenant_map_namespaces": len(tmap.namespaces)}
        if not tmap.namespaces:
            run["stats"]["warning"] = f"no tenant map for {cluster}; every request is _unmapped"
        log.info("collect %s %s: %s", cluster, day, run["stats"])
    return res.rows


def _observations(s: Settings, store: Store, day: date) -> tuple[list[dict], tuple[str, ...]]:
    """Collected rows for the day, and the clusters that have a collected file (even an empty one)."""
    rows: list[dict] = []
    present = []
    for cluster in s.collect_clusters:
        data = store.get(collect_mod.key(day, cluster))
        if data is None:
            log.warning("no collected observations for %s %s", cluster, day)
            continue
        present.append(cluster)
        rows.extend(load_jsonl_gz(data))
    return rows, tuple(present)


async def stage_enrich_and_load(s: Settings, store: Store, day: date, snapshots, loaded=None) -> dict:
    """``loaded``: an already-built ``(local, bootstrap, transfers)`` so a backfill parses the datasets once."""
    url = _db_url(s)
    observations, present = _observations(s, store, day)
    local, boot, xfer = loaded or load_local(s.work_dir / "datasets", snapshots)
    now = datetime.now(UTC)
    with connect(url, autocommit=True) as conn:     # backfills need past months' partitions
        conn.execute("SELECT ipinfo.ensure_observation_partition_for(%s)", (day,))
        submitted = submissions_mod.pending(conn, s.submit_max)
    ips = sorted({o["ip"] for o in observations} | set(submitted))

    with run_record(url, day, "enrich") as run, connect(url) as conn:
        run["snapshot_ids"] = list(local.snapshot_ids())
        current = load_current(conn, ips)
        cache = await load_network_cache(conn)
        conn.commit()
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=30) as http:
            rdap = RdapClient(boot, http, budget=s.rdap_budget) if boot else None
            resolver = RegistryResolver(cache, now, rdap=rdap, transfers=xfer)
            ns = list(s.nameservers) or dns.resolver.Resolver().nameservers
            ptr = PtrResolver(DnsPythonBackend(list(ns), timeout=s.dns_timeout), concurrency=s.concurrency)
            enricher = Enricher(local, now=now, registry=resolver, dns=ptr)
            candidates = await enricher.enrich_many(ips, {ip: v.record for ip, v in current.items()},
                                                    concurrency=s.concurrency)
        records = []
        for c in candidates:
            d = {k: v.hex() if isinstance(v, bytes) else v
                 for k, v in asdict(c.record).items() if k not in ("network", "rdap_fetch", "sources")}
            d["network"] = c.record.network.semantic() if c.record.network else None
            d["changed_layers"] = list(c.changed_layers)
            records.append(d)
        store.put(f"enrich/day={day.isoformat()}/records.jsonl.gz", dump_jsonl_gz(records))
        status_counts: dict[str, int] = {}
        for c in candidates:
            status_counts[c.record.registry_status] = status_counts.get(c.record.registry_status, 0) + 1
        run["stats"] = {"ips": len(ips), "seconds": round(time.perf_counter() - t0, 1),
                        "rdap": dict(rdap.stats) if rdap else None, "registry_status": status_counts,
                        "previous_versions": len(current), "submitted": len(submitted)}
        log.info("enrich %s: %s", day, run["stats"])

    enriched = candidates
    candidates, observations, dropped = drop_categories(candidates, observations, s.drop_categories)
    kept = {c.record.ip for c in candidates}
    with run_record(url, day, "load") as run, connect(url) as conn:
        run["snapshot_ids"] = list(local.snapshot_ids())
        run["stats"] = {**load(conn, day, candidates, current, observations, store, now=now,
                                replace_clusters=present), **dropped}
        if submitted:
            run["stats"].update(submissions_mod.mark(conn, submitted, enriched,
                                                     {c.record.ip for c in enriched} - kept))
        log.info("load %s: %s", day, run["stats"])
        return run["stats"]


def stage_maintain(s: Settings, day: date, *, drop: bool = True) -> dict:
    with run_record(_db_url(s), day, "maintain") as run, connect(_db_url(s), autocommit=True) as conn:
        created = [r[0] for r in conn.execute("SELECT * FROM ipinfo.ensure_observation_partitions(2)")]
        dropped = [r[0] for r in conn.execute("SELECT * FROM ipinfo.drop_observation_partitions(13)")] \
            if drop else []
        sizes = {r[0]: r[1] for r in conn.execute(
            "SELECT relname, pg_total_relation_size(oid) FROM pg_class WHERE relnamespace = 'ipinfo'::regnamespace "
            "AND relkind IN ('r', 'p') AND relname IN ('network', 'ip_enrichment', 'dataset_snapshot')")}
        run["stats"] = {"partitions_created": created, "partitions_dropped": dropped, "table_bytes": sizes}
        log.info("maintain: %s", run["stats"])
        return run["stats"]


def stage_refresh(s: Settings, store: Store, day: date, *, force: bool = False):
    url = _db_url(s)
    with run_record(url, day, "refresh") as run, connect(url) as conn:
        snapshots, stats = refresh(day, s.work_dir / "datasets", store, conn, force=force)
        run["snapshot_ids"] = sorted(r.snapshot_id for r in snapshots.values() if r.snapshot_id)
        run["stats"] = stats
        log.info("refresh %s: %s", day, stats)
        return snapshots


def restore_latest_snapshots(s: Settings, store: Store, day: date | None = None, dest=None) -> dict:
    """The newest recorded snapshot of each source, downloaded from S3 (into ``dest``, default
    ``<work_dir>/datasets``). ``day`` is informational only: the newest snapshot is always used."""
    from ..core.provenance import SourceRef
    from ..sources import SOURCES

    d = dest or s.work_dir / "datasets"
    d.mkdir(parents=True, exist_ok=True)
    out = {}
    with connect(_db_url(s)) as conn:
        for src in SOURCES:
            row = conn.execute("SELECT id, snapshot_date FROM ipinfo.dataset_snapshot WHERE source = %s "
                               "AND pruned_at IS NULL ORDER BY snapshot_date DESC LIMIT 1", (src.name,)).fetchone()
            if row is None:
                continue
            data = store.get(f"snapshots/{row[1].isoformat()}/{src.filename}")
            if data is None:
                continue
            (d / src.filename).write_bytes(data)
            out[src.name] = SourceRef(src.name, row[1], row[0], src.license)
    log.info("restored %d dataset snapshots from S3", len(out))
    return out


async def backfill(s: Settings, start: date, end: date) -> None:
    """Collect + enrich + load each day in [start, end], oldest first, with the latest datasets.

    Point-in-time caveat: datasets, RDAP and PTR are today's, not the day's. An
    IP that already has a newer version keeps it; that day's observations link to it.
    """
    store = open_store(s)
    snapshots = restore_latest_snapshots(s, store, end)
    loaded = load_local(s.work_dir / "datasets", snapshots)
    day = start
    while day <= end:
        for cluster in s.collect_clusters:
            try:
                await stage_collect(s, store, day, cluster)
            except Exception as exc:
                log.error("collect %s %s failed: %s", cluster, day, exc)
        try:
            await stage_enrich_and_load(s, store, day, snapshots, loaded)
        except Exception as exc:
            log.error("enrich/load %s failed: %s", day, exc)
        day += timedelta(days=1)


async def nightly(s: Settings, day: date, *, skip_collect: bool = False) -> None:
    store = open_store(s)
    stage_maintain(s, day, drop=False)
    snapshots = stage_refresh(s, store, day)
    if s.sync_tenants:
        try:
            stage_sync_tenants(s, store, day)
        except Exception as exc:   # no service account / RBAC: keep the stored map
            log.warning("sync-tenants skipped (%s); using the stored tenant map", exc)
    if not skip_collect:
        failures = []
        for cluster in s.collect_clusters:
            try:
                await stage_collect(s, store, day, cluster)
            except Exception as exc:     # one cluster's logs shouldn't block the other
                log.error("collect %s failed: %s", cluster, exc)
                failures.append(cluster)
        if len(failures) == len(s.collect_clusters):
            raise RuntimeError("collect failed for every cluster")
    await stage_enrich_and_load(s, store, day, snapshots)
    stage_maintain(s, day, drop=True)


def run_backfill(s: Settings, start: date, end: date) -> None:
    asyncio.run(backfill(s, start, end))


def run_nightly(s: Settings, day: date, **kw) -> None:
    asyncio.run(nightly(s, day, **kw))

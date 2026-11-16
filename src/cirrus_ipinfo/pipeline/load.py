"""load: one data day's enrichment candidates + observations → Postgres, in one transaction.

Rules (DESIGN.md §3, §4.2, §4.3):
* network: one row per (source, range) content; same content → bump
  last_verified_at; new content → close the old row and link superseded_by.
* ip_enrichment:
    unchanged                    → bump last_verified_at
    pending → resolved, only registry (+ derived category) changed, within 7 days
                                 → one-time fill-in of network_id and the category
                                   columns (no new version)
    changed                      → close the current version, insert a new one (valid_from = D)
  Re-running a day replaces that day's own versions in place (``same_day_replaced``),
  e.g. after a category-rules change. A day older than the IP's current version only
  bumps last_verified_at (``same_day_skipped``): history is never rewritten.
* observation: a day's rows are replaced per collected cluster (``replace_clusters`` adds clusters
  whose collected file exists but is empty), so re-running a day is idempotent and drops stale rows.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, date, datetime, timedelta

import psycopg

from ..core.enrich import Candidate
from ..core.registry.network import NetworkRecord
from .db import CurrentVersion
from .store import Store

FILL_IN_WINDOW = timedelta(days=7)


def _rdap_key(rec: NetworkRecord, fetched_at: datetime) -> str:
    handle = (rec.handle or f"{rec.start}-{rec.end}").replace("/", "_")
    return f"rdap/{rec.rir}/{handle}/{fetched_at.strftime('%Y%m%dT%H%M%SZ')}.json"


def _upsert_network(conn: psycopg.Connection, rec: NetworkRecord, fetched_at: datetime, raw_uri: str | None,
                    snapshot_id: int | None, now: datetime, stats: Counter) -> int:
    h = rec.content_hash
    cur = conn.execute(
        "SELECT id, content_hash FROM ipinfo.network WHERE source = %s AND superseded_at IS NULL "
        "AND range = ipinfo.inetrange(%s::inet, %s::inet, '[]') FOR UPDATE",
        (rec.source, str(rec.start), str(rec.end))).fetchone()
    if cur and bytes(cur[1]) == h:
        conn.execute("UPDATE ipinfo.network SET last_verified_at = greatest(last_verified_at, %s) WHERE id = %s",
                     (fetched_at, cur[0]))
        stats["network_reverified"] += 1
        return cur[0]
    if cur:
        conn.execute("UPDATE ipinfo.network SET superseded_at = %s WHERE id = %s", (max(now, fetched_at), cur[0]))
    new_id = conn.execute(
        """INSERT INTO ipinfo.network
             (range, cidrs, span, rir, source, handle, parent_handle, status, org_handle, org, netname, country,
              abuse_contact, registered_at, rir_last_changed, raw_s3_uri, snapshot_id, content_hash,
              fetched_at, last_verified_at)
           VALUES (ipinfo.inetrange(%s::inet, %s::inet, '[]'), %s::cidr[], %s, %s, %s, %s, %s, %s, %s, %s,
                   %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING id""",
        (str(rec.start), str(rec.end), rec.cidrs, rec.span, rec.rir, rec.source, rec.handle, rec.parent_handle,
         rec.status, rec.org_handle, rec.org, rec.netname, rec.country, rec.abuse_contact, rec.registered_at,
         rec.rir_last_changed, raw_uri, snapshot_id, h, fetched_at, fetched_at)).fetchone()[0]
    if cur:
        conn.execute("UPDATE ipinfo.network SET superseded_by = %s WHERE id = %s", (new_id, cur[0]))
        stats["network_changed"] += 1
    else:
        stats["network_new"] += 1
    return new_id


_ENRICH_COLS = ("ip", "valid_from", "network_id", "registry_status", "rir", "origin_asn", "origin_asns", "as_name",
                "announced_prefix", "geo_country", "geo_region", "geo_city", "ptr", "fcrdns", "ptr_status",
                "cloud_provider", "cloud_region", "cloud_service", "tor_exit", "blocklists", "special_purpose",
                "category", "subcategory", "org_domain", "org_name", "category_basis", "legacy_category",
                "content_hash", "first_verified_at", "last_verified_at", "snapshot_ids", "enricher_version",
                "changed_layers", "geo_country_name", "geo_continent", "geo_subdivisions", "geo_postal",
                "geo_timezone", "geo_lat", "geo_lon", "geo_accuracy_km", "geo_source", "ipinfo_asn",
                "ipinfo_as_name", "as_domain")
_INSERT_ENRICH = (f"INSERT INTO ipinfo.ip_enrichment ({', '.join(_ENRICH_COLS)}) "
                  f"VALUES ({', '.join(['%s'] * len(_ENRICH_COLS))}) RETURNING id")


def drop_categories(candidates: list[Candidate], observations: list[dict], drop: frozenset[str],
                    ) -> tuple[list[Candidate], list[dict], dict]:
    """Remove IPs whose ``category/subcategory`` is in ``drop`` (e.g. ``internal/k8s_node``:
    the clusters' own nodes, whose requests are infrastructure, not clients). Nothing is stored
    for them; the counts go to the run stats."""
    if not drop:
        return candidates, observations, {}
    gone = {c.record.ip for c in candidates if f"{c.record.category}/{c.record.subcategory}" in drop}
    if not gone:
        return candidates, observations, {}
    kept_obs = [o for o in observations if o["ip"] not in gone]
    stats = {"dropped_ips": len(gone), "dropped_requests": sum(o["hits"] for o in observations if o["ip"] in gone)}
    return [c for c in candidates if c.record.ip not in gone], kept_obs, stats


def _enrich_values(rec, day: date, c: Candidate, now: datetime) -> tuple:
    return (rec.ip, day, rec.network_id, rec.registry_status, rec.rir, rec.origin_asn,
            list(rec.origin_asns) or None, rec.as_name, rec.announced_prefix, rec.geo_country, rec.geo_region,
            rec.geo_city, rec.ptr, rec.fcrdns, rec.ptr_status, rec.cloud_provider, rec.cloud_region,
            rec.cloud_service, rec.tor_exit, list(rec.blocklists), rec.special_purpose, rec.category,
            rec.subcategory, rec.org_domain, rec.org_name, rec.category_basis, rec.legacy_category,
            c.content_hash, now, now, list(rec.snapshot_ids), rec.enricher_version, list(c.changed_layers),
            rec.geo_country_name, rec.geo_continent, list(rec.geo_subdivisions), rec.geo_postal, rec.geo_timezone,
            rec.geo_lat, rec.geo_lon, rec.geo_accuracy_km, rec.geo_source, rec.ipinfo_asn, rec.ipinfo_as_name,
            rec.as_domain)


def load(conn: psycopg.Connection, day: date, candidates: list[Candidate], current: dict[str, CurrentVersion],
         observations: list[dict], store: Store | None, *, now: datetime | None = None,
         replace_clusters: tuple[str, ...] = ()) -> dict:
    now = now or datetime.now(UTC)
    stats: Counter = Counter()
    with conn.transaction():
        # tenants
        names = sorted({o["tenant"] for o in observations})
        if names:
            conn.execute("INSERT INTO ipinfo.tenant (name) SELECT unnest(%s::text[]) ON CONFLICT DO NOTHING",
                         (names,))

        # networks fetched (or first seen) this run
        net_ids: dict[tuple, int] = {}
        for c in candidates:
            rec = c.record
            if rec.network is None:
                continue
            if rec.network_id is not None:
                if rec.rdap_fetch is not None:   # refetched, same content: record the confirmation
                    conn.execute("UPDATE ipinfo.network SET last_verified_at = greatest(last_verified_at, %s) "
                                 "WHERE id = %s", (rec.rdap_fetch.fetched_at, rec.network_id))
                    stats["network_reverified"] += 1
                continue
            n = rec.network
            k = (n.source, n.start, n.end, n.content_hash)
            if k in net_ids:
                rec.network_id = net_ids[k]
                continue
            fetched = rec.rdap_fetch.fetched_at if rec.rdap_fetch else (rec.registry_verified_at or now)
            raw_uri = None
            if store is not None and rec.rdap_fetch is not None and n.raw is not None:
                raw_uri = store.put(_rdap_key(n, fetched), json.dumps(n.raw).encode())
            net_ids[k] = rec.network_id = _upsert_network(conn, n, fetched, raw_uri, None, now, stats)

        # enrichment versions
        enrichment_id: dict[str, int] = {}
        for c in candidates:
            rec = c.record
            cur = current.get(rec.ip)
            if cur is not None and c.unchanged:
                conn.execute("UPDATE ipinfo.ip_enrichment SET last_verified_at = greatest(last_verified_at, %s) "
                             "WHERE id = %s", (now, cur.id))
                enrichment_id[rec.ip] = cur.id
                stats["unchanged"] += 1
                continue
            if (cur is not None and cur.record.registry_status == "pending" and rec.registry_status == "resolved"
                    and "registry" in c.changed_layers and set(c.changed_layers) <= {"registry", "category"}
                    and day - cur.valid_from <= FILL_IN_WINDOW):
                # The category columns are derived from the registry (org_name, registry org
                # keywords), so they are completed together with it.
                conn.execute("UPDATE ipinfo.ip_enrichment SET network_id = %s, registry_status = 'resolved', "
                             "rir = %s, category = %s, subcategory = %s, org_domain = %s, org_name = %s, "
                             "category_basis = %s, legacy_category = %s, "
                             "last_verified_at = greatest(last_verified_at, %s) "
                             "WHERE id = %s AND registry_status = 'pending'",
                             (rec.network_id, rec.rir, rec.category, rec.subcategory, rec.org_domain, rec.org_name,
                              rec.category_basis, rec.legacy_category, now, cur.id))
                enrichment_id[rec.ip] = cur.id
                stats["pending_filled_in"] += 1
                continue
            if cur is not None and cur.valid_from == day:
                # Re-running a day replaces that day's version (same data day, e.g. after a rules
                # change); versions of other days are never rewritten.
                cols = [col for col in _ENRICH_COLS[2:] if col not in ("first_verified_at", "changed_layers")]
                vals = dict(zip(_ENRICH_COLS, _enrich_values(rec, day, c, now), strict=True))
                sets = ", ".join(f"{col} = %s" for col in cols)
                conn.execute(f"UPDATE ipinfo.ip_enrichment SET {sets} WHERE id = %s",
                             (*(vals[col] for col in cols), cur.id))
                enrichment_id[rec.ip] = cur.id
                stats["same_day_replaced"] += 1
                continue
            if cur is not None and cur.valid_from > day:
                conn.execute("UPDATE ipinfo.ip_enrichment SET last_verified_at = greatest(last_verified_at, %s) "
                             "WHERE id = %s", (now, cur.id))
                enrichment_id[rec.ip] = cur.id
                stats["same_day_skipped"] += 1
                continue
            if cur is not None:
                conn.execute("UPDATE ipinfo.ip_enrichment SET superseded_at = %s WHERE id = %s", (now, cur.id))
                stats["changed"] += 1
                for layer in c.changed_layers:
                    stats[f"changed_{layer}"] += 1
            else:
                stats["new"] += 1
            enrichment_id[rec.ip] = conn.execute(_INSERT_ENRICH, _enrich_values(rec, day, c, now)).fetchone()[0]

        # observations
        by_ip = {c.record.ip: c.record for c in candidates}
        rows = []
        for o in observations:
            rec = by_ip.get(o["ip"])
            if rec is None or o["ip"] not in enrichment_id:
                stats["observation_without_enrichment"] += 1
                continue
            rows.append((o["day"], o["cluster"], o.get("ingress", "traefik"), o["tenant"], o["namespace"], o["host"], o["ip"], o["hits"],
                         o["hits_4xx"], o["hits_5xx"], o["bytes"], o["first_seen"], o["last_seen"],
                         enrichment_id[o["ip"]], rec.origin_asn, rec.geo_country, rec.cloud_provider,
                         bool(rec.blocklists), rec.category, rec.subcategory, rec.org_domain))
        # A day's observations are replaced per collected cluster, so a re-run also removes rows that
        # are no longer produced (e.g. IPs now dropped as cluster nodes). Clusters with nothing in this
        # load (collect failed) keep what they had.
        clusters = sorted({o["cluster"] for o in observations} | set(replace_clusters))
        if clusters:
            deleted = conn.execute("DELETE FROM ipinfo.observation WHERE day = %s AND cluster = ANY(%s)",
                                   (day, clusters)).rowcount
            stats["observations_replaced"] = deleted
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO ipinfo.observation
                     (day, cluster, ingress, tenant, namespace, host, ip, hits, hits_4xx, hits_5xx, bytes,
                      first_seen, last_seen, enrichment_id, origin_asn, geo_country, cloud_provider, blocklisted,
                      category, subcategory, org_domain)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (day, cluster, ingress, tenant, namespace, host, ip) DO UPDATE SET
                     hits = EXCLUDED.hits, hits_4xx = EXCLUDED.hits_4xx, hits_5xx = EXCLUDED.hits_5xx,
                     bytes = EXCLUDED.bytes, first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen,
                     enrichment_id = EXCLUDED.enrichment_id, origin_asn = EXCLUDED.origin_asn,
                     geo_country = EXCLUDED.geo_country, cloud_provider = EXCLUDED.cloud_provider,
                     blocklisted = EXCLUDED.blocklisted, category = EXCLUDED.category,
                     subcategory = EXCLUDED.subcategory, org_domain = EXCLUDED.org_domain""", rows)
        stats["observations"] = len(rows)
    return dict(stats)

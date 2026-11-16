"""collect: one cluster-day of Traefik access logs → per (tenant, namespace, host, ip) counts.

Runs on mlc1 for every cluster (logs come from the shared Loki via Grafana),
writes ``collected/day=D/cluster=C/observations.jsonl.gz`` and is
deterministic for a given day, so re-running overwrites with the same result
(as long as Loki still has the day).

``X-Forwarded-For`` is never used: ``ClientHost`` is the TCP peer, which is
the real client because LoxiLB preserves the source address (external Traefik
receives it via PROXY protocol).
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta

from ..core.addr import normalize
from .loki import AccessEntry, GrafanaLoki, LogSource
from .store import Store, dump_jsonl_gz
from .tenants import TenantMap

NO_NAMESPACE = "_none"


def key(day: date, cluster: str) -> str:
    return f"collected/day={day.isoformat()}/cluster={cluster}/observations.jsonl.gz"


@dataclass
class _Agg:
    hits: int = 0
    hits_4xx: int = 0
    hits_5xx: int = 0
    bytes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class CollectResult:
    day: date
    cluster: str
    rows: list[dict]
    stats: dict = field(default_factory=dict)


def _host(h: str) -> str:
    h = h.strip().lower()
    if h.startswith("["):                 # [v6]:port
        return h[1:h.find("]")] if "]" in h else h
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h or "-"


async def reduce(entries: AsyncIterable[tuple[str, str]], day: date, cluster: str,
                 tenants: TenantMap, exclude: Iterable[str] = (), ingress: str = "traefik") -> CollectResult:
    """``exclude``: CIDRs of the cluster's own pod/service networks. Requests from
    them are in-cluster traffic (probes, other pods), not clients, so they're
    counted in the stats but not stored. Other private space (e.g. a partner's
    10.116.0.0/16 coming over a VPN) is kept."""
    aggs: dict[tuple[str, str, str, str], _Agg] = {}
    excluded_nets = [ipaddress.ip_network(c) for c in exclude]
    stats = {"lines": 0, "bad_lines": 0, "bad_ip": 0, "outside_day": 0, "unmapped_lines": 0,
             "excluded_in_cluster": 0}
    lo = datetime.combine(day, time(), UTC)
    hi = lo + timedelta(days=1)
    async for ts_ns, line in entries:
        stats["lines"] += 1
        e = AccessEntry.parse(ts_ns, line)
        if e is None:
            stats["bad_lines"] += 1
            continue
        if not lo <= e.ts < hi:
            stats["outside_day"] += 1
            continue
        try:
            addr = normalize(e.client)
        except ValueError:
            stats["bad_ip"] += 1
            continue
        if excluded_nets and any(addr in n for n in excluded_nets):
            stats["excluded_in_cluster"] += 1
            continue
        ip = str(addr)
        ns = tenants.namespace_of(ingress_namespace=e.ingress_namespace, service=e.service, router=e.router)
        tenant = tenants.tenant(ns)
        if ns is None:
            stats["unmapped_lines"] += 1
        k = (tenant, ns or NO_NAMESPACE, _host(e.host), ip)
        a = aggs.get(k)
        if a is None:
            a = aggs[k] = _Agg(first_seen=e.ts, last_seen=e.ts)
        a.hits += 1
        a.hits_4xx += 400 <= e.status < 500
        a.hits_5xx += e.status >= 500
        a.bytes += e.size
        a.first_seen = min(a.first_seen, e.ts)
        a.last_seen = max(a.last_seen, e.ts)

    rows = [{"day": day.isoformat(), "cluster": cluster, "ingress": ingress, "tenant": t, "namespace": ns, "host": h, "ip": ip,
             "hits": a.hits, "hits_4xx": a.hits_4xx, "hits_5xx": a.hits_5xx, "bytes": a.bytes,
             "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat()}
            for (t, ns, h, ip), a in sorted(aggs.items())]

    per_ip: dict[str, int] = {}
    for r in rows:
        per_ip[r["ip"]] = per_ip.get(r["ip"], 0) + r["hits"]
    total = sum(per_ip.values())
    stats.update(rows=len(rows), unique_ips=len(per_ip), requests=total)
    if total:
        top = max(per_ip.values())
        stats["top_ip_share"] = round(top / total, 4)
        # A load balancer that stops preserving source addresses shows up as one
        # IP carrying nearly all traffic; flag it instead of failing silently.
        stats["source_ip_suspect"] = total >= 1000 and top / total > 0.8
    return CollectResult(day, cluster, rows, stats)


async def collect(loki: GrafanaLoki, sources: Iterable[LogSource], day: date, cluster: str,
                  tenants: TenantMap, store: Store, exclude: Iterable[str] = ()) -> CollectResult:
    """Every ingress controller's logs for one cluster-day → one collected file.

    Stats are kept per source (``stats["sources"][name]``), so a source whose log
    format doesn't match (all lines ``bad_lines``, or zero lines) is visible at once.
    """
    start = datetime.combine(day, time(), UTC)
    rows: list[dict] = []
    per_source: dict[str, dict] = {}
    for src in sources:
        res = await reduce(loki.entries(src.query(cluster), start, start + timedelta(days=1)), day, cluster,
                           tenants, exclude, ingress=src.name)
        rows.extend(res.rows)
        per_source[src.name] = res.stats
    result = CollectResult(day, cluster, rows, {
        "rows": len(rows), "unique_ips": len({r["ip"] for r in rows}),
        "requests": sum(r["hits"] for r in rows), "sources": per_source,
        "source_ip_suspect": [n for n, st in per_source.items() if st.get("source_ip_suspect")],
    })
    result.stats["s3_uri"] = store.put(key(day, cluster), dump_jsonl_gz(rows))
    return result

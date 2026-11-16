"""collect: tenant attribution, Loki pagination through Grafana, per-day reduction."""

from datetime import UTC, date, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx

from cirrus_ipinfo.pipeline.collect import reduce
from cirrus_ipinfo.pipeline.loki import AccessEntry, GrafanaLoki, LogSource
from cirrus_ipinfo.pipeline.tenants import TenantMap

TM = TenantMap({"ncote": "testtenant", "ncote-db": "dbtenant", "openbao": None, "rda": "gdex"})
DAY = date(2026, 11, 12)


def test_namespace_attribution():
    # KubernetesIngressNamespace (external Traefik) wins outright
    assert TM.namespace_of(ingress_namespace="rda", service="x", router="y") == "rda"
    # ServiceName <ns>-<svc>-<port>@kubernetes, longest namespace first
    assert TM.namespace_of(ingress_namespace="", service="ncote-db-api-8080@kubernetes", router="") == "ncote-db"
    assert TM.namespace_of(ingress_namespace="", service="ncote-web-80@kubernetescrd", router="") == "ncote"
    # RouterName <entrypoint>-<ns>-... when the service didn't match
    assert TM.namespace_of(ingress_namespace="", service="noop@internal",
                           router="websecure-openbao-openbao-bao-k8s@kubernetes") == "openbao"
    assert TM.namespace_of(ingress_namespace="", service="", router="") is None
    assert (TM.tenant("ncote-db"), TM.tenant("openbao"), TM.tenant("ghost"), TM.tenant(None)) == \
        ("dbtenant", "_platform", "_unmapped", "_unmapped")


def test_query_extracts_fields_server_side():
    q = LogSource("traefik", '{cluster="mlc1", namespace="traefik"}').query("")
    assert q.startswith('{cluster="mlc1", namespace="traefik"} |= "ClientHost" | json client="ClientHost"')
    assert 'line_format "{{.client}}\\t{{.host}}' in q


def _line(client, host="App.Example.edu:443", svc="ncote-web-80@kubernetes", status=200, size=100, ingns=""):
    return "\t".join([client, host, svc, "", ingns, str(status), str(size)])


def _ns(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1e9))


def fake_grafana(entries: list[tuple[str, str, dict]], seen: list[dict]):
    """Serves query_range like Loki: inclusive start, exclusive end, forward, limit."""
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/datasources/proxy/uid/loki-uid/loki/api/v1/query_range"
        assert req.headers["Authorization"] == "Bearer tok"
        q = {k: v[0] for k, v in parse_qs(urlparse(str(req.url)).query).items()}
        seen.append(q)
        start, end, limit = int(q["start"]), int(q["end"]), int(q["limit"])
        hits = sorted((e for e in entries if start <= int(e[0]) < end), key=lambda e: int(e[0]))[:limit]
        streams: dict[str, dict] = {}
        for ts, line, labels in hits:
            s = streams.setdefault(repr(sorted(labels.items())), {"stream": labels, "values": []})
            s["values"].append([ts, line])
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams",
                                                                        "result": list(streams.values())}})
    return httpx.MockTransport(handler)


async def test_loki_paginates_without_loss_or_duplicates():
    t0 = datetime(2026, 11, 12, 0, 0, tzinfo=UTC)
    entries = []
    for i in range(23):
        ts = _ns(t0 + timedelta(minutes=10 * i))
        entries.append((ts, _line(f"192.0.2.{i}"), {"pod": "a"}))
        if i % 5 == 0:   # same nanosecond on another pod: must survive the page boundary
            entries.append((ts, _line(f"198.51.100.{i}"), {"pod": "b"}))
    seen: list[dict] = []
    async with httpx.AsyncClient(transport=fake_grafana(entries, seen)) as http:
        loki = GrafanaLoki(http, "https://grafana.test", "loki-uid", "tok", page_limit=3)
        got = [x async for x in loki.entries("q", t0, t0 + timedelta(hours=4))]
    assert sorted(got) == sorted((ts, line) for ts, line, _ in entries)
    assert len(seen) > 4 and all(q["direction"] == "forward" for q in seen)


async def test_reduce_counts_per_tenant_host_ip():
    t = datetime(2026, 11, 12, 13, 0, tzinfo=UTC)

    async def gen():
        yield _ns(t), _line("128.138.1.1")
        yield _ns(t + timedelta(seconds=5)), _line("128.138.1.1", status=404, size=10)
        yield _ns(t + timedelta(seconds=9)), _line("::ffff:128.138.1.1", status=502)   # v4-mapped → same IP
        yield _ns(t), _line("2001:db8::1", host="[2001:db8::5]:443", svc="rda-web-80@kubernetes", ingns="rda")
        yield _ns(t), _line("203.0.113.9", svc="", host="unknown.example")
        yield _ns(t - timedelta(days=1)), _line("128.138.1.1")       # yesterday: dropped
        yield _ns(t), "garbage"
        yield _ns(t), _line("not-an-ip")

    res = await reduce(gen(), DAY, "mlc1", TM)
    rows = {(r["tenant"], r["namespace"], r["host"], r["ip"]): r for r in res.rows}
    cu = rows[("testtenant", "ncote", "app.example.edu", "128.138.1.1")]
    assert (cu["hits"], cu["hits_4xx"], cu["hits_5xx"], cu["bytes"]) == (3, 1, 1, 210)
    assert cu["first_seen"] < cu["last_seen"]
    assert ("gdex", "rda", "2001:db8::5", "2001:db8::1") in rows
    assert ("_unmapped", "_none", "unknown.example", "203.0.113.9") in rows
    assert res.stats["outside_day"] == 1 and res.stats["bad_lines"] == 1 and res.stats["bad_ip"] == 1
    assert res.stats["unique_ips"] == 3 and res.stats["source_ip_suspect"] is False


def test_access_entry_parse():
    e = AccessEntry.parse(_ns(datetime(2026, 11, 12, tzinfo=UTC)), _line("192.0.2.1", status=200, size=5))
    assert e is not None and e.status == 200 and e.size == 5 and e.ts.tzinfo is UTC
    assert AccessEntry.parse("1", "too\tfew") is None


async def test_reduce_drops_in_cluster_networks_but_keeps_other_private_space():
    t = datetime(2026, 11, 12, 13, 0, tzinfo=UTC)

    async def gen():
        yield _ns(t), _line("10.0.7.180")      # Cilium pod (probe) → dropped
        yield _ns(t), _line("10.98.1.1")       # service network → dropped
        yield _ns(t), _line("10.116.4.2")      # partner private space → kept

    res = await reduce(gen(), DAY, "mlc1", TM, exclude=["10.0.0.0/16", "10.96.0.0/12"])
    assert [r["ip"] for r in res.rows] == ["10.116.4.2"]
    assert res.stats["excluded_in_cluster"] == 2



def test_nginx_default_format_query_and_attribution():
    from cirrus_ipinfo.pipeline.loki import LogSource
    q = LogSource("ingress-nginx", '{cluster="{cluster}", namespace="ingress-nginx"}', "nginx").query("mlc1")
    assert q.startswith('{cluster="mlc1", namespace="ingress-nginx"} |~ `')
    assert "(?P<upstream>" in q and "@nginx" in q
    # the upstream "<ns>-<svc>-<port>" maps to the namespace like a Traefik ServiceName does
    assert TM.namespace_of(ingress_namespace="", service="rda-web-80@nginx", router="") == "rda"
    assert TM.namespace_of(ingress_namespace="", service="upstream-default-backend@nginx", router="") is None
    assert TM.namespace_of(ingress_namespace="", service="rda-web-80", router="") == "rda"   # JSON format


def test_json_source_needs_client_and_status():
    import pytest as _pytest

    from cirrus_ipinfo.pipeline.loki import LogSource
    with _pytest.raises(ValueError):
        LogSource("x", "{a=\"b\"}", "json", {"host": "host"}).query("c")


async def test_collect_merges_sources_with_ingress_column():
    from cirrus_ipinfo.pipeline.collect import collect
    from cirrus_ipinfo.pipeline.loki import LogSource
    from cirrus_ipinfo.pipeline.store import LocalStore

    t = datetime(2026, 11, 12, 13, 0, tzinfo=UTC)

    class FakeLoki:
        async def entries(self, query, start, end):
            if "ingress-nginx" in query:
                yield _ns(t), "\t".join(["203.0.113.5", "rda-web-80", "rda-web-80@nginx", "", "", "200", "10"])
            else:
                yield _ns(t), _line("198.51.100.7")

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        res = await collect(FakeLoki(), [LogSource("traefik", "{n=\"traefik\"}"),
                                         LogSource("ingress-nginx", "{n=\"ingress-nginx\"}", "nginx")],
                            DAY, "mlc1", TM, LocalStore(d))
    by = {r["ingress"]: r for r in res.rows}
    assert by["ingress-nginx"]["namespace"] == "rda" and by["ingress-nginx"]["tenant"] == "gdex"
    assert by["traefik"]["namespace"] == "ncote"
    assert set(res.stats["sources"]) == {"traefik", "ingress-nginx"} and res.stats["requests"] == 2


async def test_drop_categories_removes_nodes():
    from cirrus_ipinfo.core.enrich import Candidate
    from cirrus_ipinfo.pipeline.load import drop_categories

    def cand(ip, cat, sub):
        from cirrus_ipinfo.core.model import EnrichmentRecord
        return Candidate(EnrichmentRecord(ip=ip, registry_status="resolved", category=cat, subcategory=sub), b"", ())

    cands = [cand("128.117.217.72", "internal", "k8s_node"), cand("128.117.65.84", "internal", "ncar_ucar")]
    obs = [{"ip": "128.117.217.72", "hits": 38504}, {"ip": "128.117.65.84", "hits": 3}]
    c2, o2, st = drop_categories(cands, obs, frozenset({"internal/k8s_node"}))
    assert [c.record.ip for c in c2] == ["128.117.65.84"] and [o["ip"] for o in o2] == ["128.117.65.84"]
    assert st == {"dropped_ips": 1, "dropped_requests": 38504}

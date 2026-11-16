"""RPSL dumps, RDAP parsing/client, transfers, and the dump → cache → RDAP resolver."""

from datetime import timedelta

import httpx
import pytest

from cirrus_ipinfo.core.localdb import LocalData
from cirrus_ipinfo.core.registry.network import NetworkRecord
from cirrus_ipinfo.core.registry.rdap import (
    RdapBudgetExhausted,
    RdapClient,
    RdapNotFound,
    RdapRateLimited,
    parse_rdap_network,
)
from cirrus_ipinfo.core.registry.resolve import (
    CachedNetwork,
    InMemoryNetworkCache,
    RefetchPolicy,
    RegistryResolver,
)
from cirrus_ipinfo.core.registry.rpsl import iter_objects
from cirrus_ipinfo.core.registry.transfers import TransferLog
from tests.conftest import NOW, FakeClock, ip, rdap_doc, rdap_transport

RDAP_8888 = "https://rdap.arin.net/registry/ip/8.8.8.8"


# ------------------------------------------------------------------ RPSL
def test_rpsl_continuation_and_comments():
    objs = list(iter_objects([
        "% comment\n", "inetnum: 1.0.0.0 - 1.0.0.255\n", "descr:   first\n", "+        second\n",
        "\t third\n", "source:  RIPE # remark\n", "\n", "role: R\n", "nic-hdl: X\n",
    ]))
    assert objs[0][1]["descr"] == ["first second third"]
    assert objs[0][1]["source"] == ["RIPE"]
    assert objs[1][0] == "role"


def test_rpsl_records_resolve_org_and_abuse(ripe_db):
    recs = {r.handle: r for r in ripe_db.records()}
    big = recs["193.0.0.0 - 193.0.7.255"]
    assert big.org == "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"
    assert big.abuse_contact == "abuse@ripe.net"
    assert (big.rir, big.source, big.country) == ("ripencc", "ripe_dump", "NL")
    small = recs["193.0.0.0 - 193.0.0.99"]
    assert small.org == "Small fixture assignment with a continuation line"   # descr fallback
    assert small.country == "DE"
    assert small.cidrs == ["193.0.0.0/26", "193.0.0.64/27", "193.0.0.96/30"]
    v6 = recs["2001:67c:2e8::/48"]
    assert v6.abuse_contact == "abuse@ripe.net"   # via organisation abuse-c


def test_dump_index_most_specific(ripe_db):
    idx = LocalData.build_registry_index(ripe_db.records())
    assert idx.lookup(ip("193.0.0.50")).netname == "FIXTURE-SMALL"
    assert idx.lookup(ip("193.0.0.100")).netname == "RIPE-NCC"
    assert idx.lookup(ip("2001:67c:2e8::1")).netname == "RIPE-NCC-V6"


# ------------------------------------------------------------------ RDAP
def test_bootstrap_routes_to_rirs(bootstrap):
    assert bootstrap.base_url(ip("8.8.8.8")) == "https://rdap.arin.net/registry/"
    assert bootstrap.base_url(ip("193.0.0.1")) == "https://rdap.db.ripe.net/"
    assert bootstrap.base_url(ip("2001:67c:2e8::1")) == "https://rdap.db.ripe.net/"
    assert bootstrap.base_url(ip("200.1.1.1")) == "https://rdap.lacnic.net/rdap/"


def test_parse_rdap_nested_abuse():
    rec = parse_rdap_network(rdap_doc(), "arin")
    assert (str(rec.start), str(rec.end)) == ("8.8.8.0", "8.8.8.255")
    assert (rec.org, rec.org_handle, rec.netname) == ("Google LLC", "GOGL", "GOGL")
    assert rec.abuse_contact == "network-abuse@google.com"
    assert rec.parent_handle == "NET-8-0-0-0-0"
    assert rec.registered_at.year == 2023


def _client(bootstrap, routes, calls, clock=None, **kw):
    clock = clock or FakeClock()
    http = httpx.AsyncClient(transport=rdap_transport(routes, calls))
    return RdapClient(bootstrap, http, clock=clock, sleep=clock.sleep, now=lambda: NOW, **kw), clock


async def test_rdap_client_ok(bootstrap):
    calls = []
    client, _ = _client(bootstrap, {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc())}, calls)
    res = await client.lookup(ip("8.8.8.8"))
    assert res.record.org == "Google LLC" and calls == [RDAP_8888]
    assert client.stats["ok"] == 1


async def test_rdap_429_honours_retry_after(bootstrap):
    calls = []
    routes = {"/ip/8.8.8.8": [httpx.Response(429, headers={"Retry-After": "7"}),
                              httpx.Response(200, json=rdap_doc())]}
    client, clock = _client(bootstrap, routes, calls)
    res = await client.lookup(ip("8.8.8.8"))
    assert res.record.handle == "NET-8-8-8-0-2"
    assert 7.0 in clock.sleeps and client.stats["http_429"] == 1 and len(calls) == 2


async def test_rdap_429_gives_up(bootstrap):
    client, _ = _client(bootstrap, {"/ip/8.8.8.8": httpx.Response(429)}, [], max_retries=2)
    with pytest.raises(RdapRateLimited):
        await client.lookup(ip("8.8.8.8"))


async def test_rdap_budget(bootstrap):
    client, _ = _client(bootstrap, {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc())}, [], budget=1)
    await client.lookup(ip("8.8.8.8"))
    with pytest.raises(RdapBudgetExhausted):
        await client.lookup(ip("8.8.8.8"))


async def test_rdap_404(bootstrap):
    client, _ = _client(bootstrap, {}, [])
    with pytest.raises(RdapNotFound):
        await client.lookup(ip("8.8.8.8"))


async def test_rdap_redirect_sets_rir_from_final_url(bootstrap):
    doc = rdap_doc() | {"handle": "TRANSFERRED"}

    def handler(request):
        if request.url.host == "rdap.arin.net":
            return httpx.Response(302, headers={"Location": "https://rdap.db.ripe.net/ip/8.8.8.8"})
        return httpx.Response(200, json=doc)

    clock = FakeClock()
    client = RdapClient(bootstrap, httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                        clock=clock, sleep=clock.sleep, now=lambda: NOW)
    res = await client.lookup(ip("8.8.8.8"))
    assert res.record.rir == "ripencc"


async def test_token_bucket_spaces_requests(bootstrap):
    calls = []
    client, clock = _client(bootstrap, {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc())}, calls,
                            rates={"arin": (1.0, 1)})
    for _ in range(3):
        await client.lookup(ip("8.8.8.8"))
    assert len(calls) == 3 and clock.t == pytest.approx(2.0)


# ------------------------------------------------------------- transfers
def test_transfer_log_real_format():
    doc = {"transfers": [{
        "transfer_date": "2026-11-01T19:00:00Z",
        "ip4nets": {"original_set": [{"start_address": "8.8.0.0", "end_address": "8.8.255.255"}],
                    "transfer_set": [{"start_address": "8.8.8.0", "end_address": "8.8.8.255"}]},
        "type": "RESOURCE_TRANSFER", "source_rir": "ARIN", "recipient_rir": "ARIN",
    }]}
    log = TransferLog.from_docs(doc)
    assert log.transferred_since(ip("8.8.8.8"), NOW - timedelta(days=30))
    assert not log.transferred_since(ip("8.8.8.8"), NOW)
    assert not log.transferred_since(ip("8.8.9.1"), NOW - timedelta(days=30))   # only transfer_set counts


# -------------------------------------------------------------- resolver
def _arin(org="Google LLC", handle="NET-8-8-8-0-2") -> NetworkRecord:
    return NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", handle=handle, org=org)


async def _resolver(bootstrap, routes, calls, cache=None, transfers=None, **kw):
    client, _ = _client(bootstrap, routes, calls, **kw)
    return RegistryResolver(cache=cache or InMemoryNetworkCache(), now=NOW, rdap=client,
                            transfers=transfers, policy=RefetchPolicy())


async def test_resolver_uses_dump_for_dump_rirs(bootstrap, local):
    calls = []
    r = await _resolver(bootstrap, {}, calls)
    r.dumps = local.registry_dumps
    out = await r.resolve(ip("193.0.0.10"), rir="ripencc")
    assert (out.status, out.source, out.network.netname) == ("resolved", "ripe_dump", "FIXTURE-SMALL")
    assert calls == []


async def test_resolver_fresh_cache_no_rdap(bootstrap):
    cache = InMemoryNetworkCache()
    await cache.put(CachedNetwork(_arin(), NOW - timedelta(days=10), network_id=42))
    calls = []
    r = await _resolver(bootstrap, {}, calls, cache=cache)
    out = await r.resolve(ip("8.8.8.8"), rir="arin")
    assert (out.status, out.source, out.network_id, out.refetch_reasons) == ("resolved", "cache", 42, ())
    assert calls == []


@pytest.mark.parametrize("kwargs,reason", [
    ({}, "stale"),
    ({"routing_changed": True}, "routing_change"),
    ({"delegation_changed": True}, "delegation_change"),
])
async def test_resolver_refetch_reasons(bootstrap, kwargs, reason):
    age = timedelta(days=120) if reason == "stale" else timedelta(days=1)
    cache = InMemoryNetworkCache()
    same_as_rdap = parse_rdap_network(rdap_doc(), "arin")
    await cache.put(CachedNetwork(same_as_rdap, NOW - age, network_id=42))
    calls = []
    r = await _resolver(bootstrap, {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc())}, calls, cache=cache)
    out = await r.resolve(ip("8.8.8.8"), rir="arin", **kwargs)
    assert reason in out.refetch_reasons and out.source == "rdap" and len(calls) == 1
    assert out.network_id == 42   # same content → same network row


async def test_resolver_transfer_signal_and_changed_owner(bootstrap):
    cache = InMemoryNetworkCache()
    await cache.put(CachedNetwork(_arin(org="Old Owner Inc", handle="NET-OLD"), NOW - timedelta(days=5), 7))
    log = TransferLog([(ip("8.8.8.0"), ip("8.8.8.255"), NOW - timedelta(days=1))])
    calls = []
    r = await _resolver(bootstrap, {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc())}, calls,
                        cache=cache, transfers=log)
    out = await r.resolve(ip("8.8.8.8"), rir="arin")
    assert out.refetch_reasons == ("transfer",)
    assert out.network.org == "Google LLC" and out.network_id is None   # new content → new network row


async def test_resolver_budget_exhausted_pending_or_cached(bootstrap):
    calls = []
    r = await _resolver(bootstrap, {}, calls, budget=0)
    out = await r.resolve(ip("8.8.8.8"), rir="arin")
    assert (out.status, out.refetch_reasons) == ("pending", ("missing",))

    cache = InMemoryNetworkCache()
    await cache.put(CachedNetwork(_arin(), NOW - timedelta(days=200), 9))
    r = await _resolver(bootstrap, {}, calls, cache=cache, budget=0)
    out = await r.resolve(ip("8.8.8.8"), rir="arin")
    assert (out.status, out.source, out.refetch_reasons) == ("resolved", "cache", ("stale",))
    assert calls == []


async def test_resolver_not_found_is_failed(bootstrap):
    r = await _resolver(bootstrap, {}, [])
    out = await r.resolve(ip("8.8.8.8"), rir="arin")
    assert out.status == "failed"


async def test_resolver_dedupes_within_run(bootstrap):
    calls = []
    routes = {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc()),
              "/ip/8.8.8.9": httpx.Response(200, json=rdap_doc())}
    r = await _resolver(bootstrap, routes, calls)
    a = await r.resolve(ip("8.8.8.8"), rir="arin")
    b = await r.resolve(ip("8.8.8.9"), rir="arin", routing_changed=True)
    assert len(calls) == 1
    assert a.network == b.network and b.source == "cache"


async def test_in_memory_cache_wide_ranges():
    cache = InMemoryNetworkCache()
    wide = NetworkRecord(ip("8.0.0.0"), ip("8.255.255.255"), "arin", "rdap", handle="WIDE")
    await cache.put(CachedNetwork(wide, NOW))
    await cache.put(CachedNetwork(_arin(), NOW))
    assert (await cache.lookup(ip("8.8.8.8"))).record.handle == "NET-8-8-8-0-2"
    assert (await cache.lookup(ip("8.200.0.1"))).record.handle == "WIDE"
    assert await cache.lookup(ip("9.0.0.1")) is None


def test_network_hash_ignores_timestamp_offset():
    from datetime import datetime, timedelta, timezone

    from cirrus_ipinfo.core.registry.network import NetworkRecord
    est = datetime(2023, 12, 28, 17, 24, 33, tzinfo=timezone(timedelta(hours=-5)))
    a = NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", registered_at=est)
    b = NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", registered_at=est.astimezone(timezone.utc))
    assert a.content_hash == b.content_hash

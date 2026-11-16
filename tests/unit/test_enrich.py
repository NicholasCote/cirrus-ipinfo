"""Classification, DNS, hashing/versioning and end-to-end enrichment."""

import dataclasses
from datetime import timedelta

import dns.exception
import dns.resolver
import httpx
import pytest

from cirrus_ipinfo.core.classify import parse_spamhaus_drop
from cirrus_ipinfo.core.dns import PtrResolver
from cirrus_ipinfo.core.enrich import Enricher
from cirrus_ipinfo.core.hashing import changed_layers, content_hash, enricher_version
from cirrus_ipinfo.core.model import EnrichmentRecord
from cirrus_ipinfo.core.registry.network import NetworkRecord
from cirrus_ipinfo.core.registry.rdap import RdapClient
from cirrus_ipinfo.core.registry.resolve import (
    CachedNetwork,
    InMemoryNetworkCache,
    RegistryResolver,
)
from tests.conftest import DROP_V4, NOW, FakeClock, ip, rdap_doc, rdap_transport


# --------------------------------------------------------- classification
def test_cloud_specific_service_beats_generic(local):
    c = local.classifier.classify(ip("3.5.141.7"))
    assert (c.cloud_provider, c.cloud_region, c.cloud_service) == ("aws", "ap-northeast-2", "EC2")
    assert local.classifier.classify(ip("2600:1f18::1")).cloud_service == "AMAZON"


def test_flags_tor_and_blocklists(local):
    c = local.classifier.classify(ip("185.220.101.1"))
    assert c.tor_exit and c.blocklists == ("firehol_level1",)
    assert not local.classifier.classify(ip("185.220.101.9")).tor_exit
    assert local.classifier.classify(ip("45.0.3.3")).blocklists == ("spamhaus_drop",)


def test_drop_ndjson_skips_metadata():
    assert [str(n) for n in parse_spamhaus_drop(DROP_V4.splitlines())] == ["45.0.0.0/16"]


# -------------------------------------------------------------------- DNS
class FakeDns:
    def __init__(self, ptr=None, fwd=None, exc=None):
        self._ptr, self._fwd, self._exc = ptr or {}, fwd or {}, exc

    async def ptr(self, addr):
        if self._exc:
            raise self._exc
        if str(addr) not in self._ptr:
            raise dns.resolver.NXDOMAIN()
        return self._ptr[str(addr)]

    async def forward(self, name, version):
        return self._fwd.get(name, [])


async def test_fcrdns_confirmed_and_not():
    r = PtrResolver(FakeDns(
        ptr={"8.8.8.8": ["dns.google"], "193.0.0.1": ["b.example", "a.example"]},
        fwd={"dns.google": ["8.8.8.8"], "a.example": ["10.0.0.1"], "b.example": ["10.0.0.2"]},
    ))
    ok = await r.lookup(ip("8.8.8.8"))
    assert (ok.ptr, ok.fcrdns, ok.status) == ("dns.google", True, "ok")
    no = await r.lookup(ip("193.0.0.1"))
    assert (no.ptr, no.fcrdns) == ("a.example", False)       # deterministic: first sorted
    assert (await r.lookup(ip("1.1.1.1"))).status == "nxdomain"


async def test_fcrdns_ipv6_text_forms_compare_equal():
    r = PtrResolver(FakeDns(ptr={"2001:67c:2e8::1": ["v6.example"]},
                            fwd={"v6.example": ["2001:067c:02e8:0000::0001"]}))
    assert (await r.lookup(ip("2001:67c:2e8::1"))).fcrdns is True


async def test_dns_timeout_status():
    r = PtrResolver(FakeDns(exc=dns.exception.Timeout()))
    assert (await r.lookup(ip("8.8.8.8"))).status == "timeout"


# --------------------------------------------------------------- hashing
def _rec(**kw) -> EnrichmentRecord:
    base = dict(ip="8.8.8.8", registry_status="resolved", origin_asn=15169, origin_asns=(15169,),
                announced_prefix="8.8.8.0/24", geo_country="US", ptr="dns.google", fcrdns=True,
                ptr_status="ok", enricher_version=enricher_version(1))
    return EnrichmentRecord(**(base | kw))


def test_hash_ignores_provenance():
    a = _rec(verified_at=NOW)
    b = _rec(verified_at=NOW + timedelta(days=1), snapshot_ids=(1, 2, 3))
    assert content_hash(a) == content_hash(b)
    assert changed_layers(a, b) == ()


def test_changed_layers():
    a = _rec()
    assert changed_layers(None, a) == ("initial",)
    assert changed_layers(a, _rec(ptr="other.example")) == ("ptr",)
    assert changed_layers(a, _rec(origin_asn=1, origin_asns=(1,), geo_country="DE")) == ("geo", "routing")
    net = NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", org="Google LLC")
    assert changed_layers(a, _rec(network=net)) == ("registry",)


def test_enricher_only_change():
    old = _rec(enricher_version="0.0.9+h0")
    new = _rec()
    assert changed_layers(old, new) == ("enricher",)
    assert content_hash(old) != content_hash(new)


def test_network_hash_from_db_row_matches_record():
    net = NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", org="Google LLC")
    from_db = _rec(network_hash=net.content_hash)     # DB rows carry only network.content_hash
    assert changed_layers(from_db, _rec(network=net)) == ()


# ------------------------------------------------------------ end-to-end
def _enricher(local, bootstrap, *, cache=None, calls=None, budget=None, dns_backend=None):
    calls = [] if calls is None else calls
    clock = FakeClock()
    rdap = RdapClient(bootstrap, httpx.AsyncClient(transport=rdap_transport(
        {"/ip/8.8.8.8": httpx.Response(200, json=rdap_doc()),
         "/ip/8.8.4.4": httpx.Response(200, json=rdap_doc())}, calls)),
        clock=clock, sleep=clock.sleep, now=lambda: NOW, budget=budget)
    reg = RegistryResolver(cache=cache or InMemoryNetworkCache(), now=NOW,
                           dumps=local.registry_dumps, rdap=rdap, transfers=local.transfers)
    return Enricher(local, now=NOW, registry=reg,
                    dns=PtrResolver(dns_backend or FakeDns(ptr={"8.8.8.8": ["dns.google"]},
                                                           fwd={"dns.google": ["8.8.8.8"]})))


async def test_ripe_v4_from_dump(local, bootstrap):
    calls = []
    rec = await _enricher(local, bootstrap, calls=calls).enrich("193.0.2.5")
    assert (rec.registry_status, rec.registry_source, rec.rir) == ("resolved", "ripe_dump", "ripencc")
    assert rec.network.org.startswith("Reseaux IP Europeens")
    assert (rec.origin_asn, rec.announced_prefix) == (3333, "193.0.0.0/21")
    assert (rec.geo_country, rec.geo_region, rec.geo_city) == ("NL", "North Holland", "Amsterdam")
    assert rec.ptr_status == "nxdomain" and calls == []
    assert {s.source for s in rec.sources["geo"]} == {"ipinfo_lite", "dbip_city_lite", "geolite2_city"}
    # GeoLite2 has no record for this block, so detail comes from DB-IP (no postal code / time zone)
    assert (rec.geo_source, rec.geo_postal, rec.geo_timezone, rec.geo_country_name) == (
        "dbip_city_lite", None, None, "Netherlands")


async def test_full_geo_from_geolite2_and_ipinfo_as_label(local, bootstrap):
    rec = await _enricher(local, bootstrap).enrich("8.8.8.8")
    assert (rec.geo_country, rec.geo_country_name, rec.geo_continent) == ("US", "United States", "NA")
    assert (rec.geo_region, rec.geo_subdivisions, rec.geo_city) == ("California", ("California",), "Mountain View")
    assert (rec.geo_postal, rec.geo_timezone, rec.geo_accuracy_km) == ("94043", "America/Los_Angeles", 1000)
    assert (rec.geo_lat, rec.geo_lon, rec.geo_source) == (37.4223, -122.085, "geolite2_city")
    assert (rec.ipinfo_asn, rec.ipinfo_as_name, rec.as_domain) == (15169, "Google LLC", "google.com")
    assert rec.as_name == "GOOGLE - Google LLC"          # routing's AS name stays RIPE asn.txt's


def test_asinfo_is_its_own_layer():
    a = _rec(ipinfo_as_name="Google LLC")
    assert changed_layers(a, _rec(ipinfo_as_name="Google")) == ("asinfo",)
    assert changed_layers(a, _rec(ipinfo_as_name="Google LLC", geo_postal="94043")) == ("geo",)


async def test_ipv6(local, bootstrap):
    rec = await _enricher(local, bootstrap).enrich("2001:67c:2e8::42")
    assert (rec.network.netname, rec.origin_asn, rec.geo_city) == ("RIPE-NCC-V6", 3333, "Amsterdam")


async def test_arin_via_rdap_with_fcrdns(local, bootstrap):
    calls = []
    rec = await _enricher(local, bootstrap, calls=calls).enrich("8.8.8.8")
    assert (rec.registry_status, rec.registry_source, rec.network.org) == ("resolved", "rdap", "Google LLC")
    assert rec.rdap_fetch is not None and len(calls) == 1
    assert (rec.ptr, rec.fcrdns, rec.as_name) == ("dns.google", True, "GOOGLE - Google LLC")
    assert any(s.source == "rdap" for s in rec.sources["registry"])


async def test_mapped_ipv4_is_enriched_as_ipv4(local, bootstrap):
    rec = await _enricher(local, bootstrap).enrich("::ffff:193.0.2.5")
    assert rec.ip == "193.0.2.5" and rec.special_purpose is None and rec.origin_asn == 3333


@pytest.mark.parametrize("addr", ["10.1.2.3", "fd12::1", "100.64.1.1", "192.168.1.1"])
async def test_special_purpose_short_circuits(local, bootstrap, addr):
    calls = []
    rec = await _enricher(local, bootstrap, calls=calls).enrich(addr)
    assert rec.special_purpose is not None
    assert (rec.registry_status, rec.ptr_status, rec.blocklists) == ("not_applicable", "skipped", ())
    assert calls == []   # FireHOL lists 10/8 and 192.168/16, but it must never be consulted


async def test_cloud_and_geo_disagreement(local, bootstrap):
    rec = await _enricher(local, bootstrap, budget=0).enrich("3.5.141.7")
    assert (rec.cloud_provider, rec.cloud_service) == ("aws", "EC2")
    assert (rec.geo_country, rec.geo_region, rec.geo_city) == ("KR", None, None)   # DB-IP said JP
    assert rec.registry_status == "pending"                                       # no RDAP budget


async def test_moas_and_blocklist(local, bootstrap):
    rec = await _enricher(local, bootstrap, budget=0).enrich("45.0.9.9")
    assert rec.origin_asns == (64500, 64501) and rec.blocklists == ("spamhaus_drop",)


async def test_changed_ownership_creates_registry_change(local, bootstrap):
    """Yesterday the cache said 'Old Owner'; a transfer fires; today RDAP says Google."""
    cache = InMemoryNetworkCache()
    old_net = NetworkRecord(ip("8.8.8.0"), ip("8.8.8.255"), "arin", "rdap", handle="NET-OLD", org="Old Owner Inc")
    await cache.put(CachedNetwork(old_net, NOW - timedelta(days=3), network_id=1))
    enr = _enricher(local, bootstrap, cache=cache)
    enr.registry.transfers = type(local.transfers)([(ip("8.8.8.0"), ip("8.8.8.255"), NOW - timedelta(days=1))])

    yesterday = dataclasses.replace(await Enricher(local, now=NOW).enrich("8.8.8.8"),
                                    registry_status="resolved", network=old_net, network_hash=None,
                                    rir="arin", ptr="dns.google", fcrdns=True, ptr_status="ok")
    yesterday.__post_init__()
    enr._categorize(yesterday)   # DB rows carry a category consistent with their layers
    cand = await enr.candidate("8.8.8.8", prev=yesterday)
    assert cand.record.network.org == "Google LLC"
    assert "transfer" in cand.record.registry_refetch_reasons
    assert cand.changed_layers == ("category", "registry")   # org_name follows the new owner
    assert not cand.unchanged


async def test_unchanged_reverification_and_transient_ptr(local, bootstrap):
    enr = _enricher(local, bootstrap)
    first = await enr.candidate("193.0.2.5")
    assert first.changed_layers == ("initial",)
    prev = enr._categorize(dataclasses.replace(first.record, ptr="host.example", fcrdns=True, ptr_status="ok"))

    flaky = _enricher(local, bootstrap, dns_backend=FakeDns(exc=dns.exception.Timeout()))
    again = await flaky.candidate("193.0.2.5", prev=prev)
    assert again.unchanged                       # timeout carried previous PTR forward
    assert again.record.ptr == "host.example"


async def test_enrich_many_without_registry_is_pending(local):
    out = await Enricher(local, now=NOW).enrich_many(["8.8.8.8", "::ffff:8.8.8.8", "10.0.0.1"])
    assert [c.record.ip for c in out] == ["8.8.8.8", "8.8.8.8", "10.0.0.1"]
    assert out[0].record.registry_status == "pending"
    assert out[2].record.registry_status == "not_applicable"

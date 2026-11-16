"""Address normalisation, range index, special-purpose, routing, delegated stats."""

import ipaddress

import pytest

from cirrus_ipinfo.core.addr import normalize
from cirrus_ipinfo.core.rangeindex import DualRangeIndex, RangeIndex
from cirrus_ipinfo.core.registry.delegated import parse_delegated
from cirrus_ipinfo.core.routing import AsNames, RoutingTable
from cirrus_ipinfo.core.special import SpecialPurpose
from tests.conftest import DELEGATED, ip


# ------------------------------------------------------------------ addr
@pytest.mark.parametrize("raw,expected", [
    ("::ffff:8.8.8.8", "8.8.8.8"),          # dual-stack Traefik logs v4 clients like this
    ("[2001:db8::1]", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1"),
    (" 193.0.0.1 ", "193.0.0.1"),
])
def test_normalize(raw, expected):
    assert str(normalize(raw)) == expected


# ------------------------------------------------------------ rangeindex
def test_most_specific_nested_and_partial_overlap():
    idx = RangeIndex.build([(0, 99, "outer"), (10, 19, "inner"), (15, 30, "overlap")])
    assert idx.lookup_int(5) == "outer"
    assert idx.lookup_int(12) == "inner"
    assert idx.lookup_int(17) == "inner"      # inner (10 wide) beats overlap (16 wide)
    assert idx.lookup_int(25) == "overlap"
    assert idx.lookup_int(50) == "outer"
    assert idx.lookup_int(100) is None


def test_priority_breaks_ties():
    idx = RangeIndex.build([(0, 9, "generic"), (0, 9, "specific")], priority=lambda v: v == "generic")
    assert idx.lookup_int(3) == "specific"


def test_union_mode_and_segment_merging():
    idx = RangeIndex.build([(0, 9, "a"), (5, 14, "b"), (10, 19, "a")], mode="union")
    assert idx.lookup_int(2) == {"a"}
    assert idx.lookup_int(7) == {"a", "b"}
    assert idx.lookup_int(12) == {"a", "b"}
    assert idx.lookup_int(17) == {"a"}
    assert idx.lookup_int(20) is None
    assert len(idx) == 3   # [0-4]{a}, [5-14]{a,b}, [15-19]{a}


def test_families_never_mix():
    idx = DualRangeIndex.from_networks([(ipaddress.ip_network("0.0.0.0/0"), "v4-all")])
    assert idx.lookup(ip("1.2.3.4")) == "v4-all"
    assert idx.lookup(ip("::1.2.3.4")) is None


# --------------------------------------------------------------- special
SP = SpecialPurpose.default()


@pytest.mark.parametrize("addr,name", [
    ("10.1.2.3", "Private-Use"),
    ("100.64.0.1", "Shared Address Space"),
    ("127.0.0.1", "Loopback"),
    ("169.254.1.1", "Link Local"),
    ("192.0.2.10", "Documentation (TEST-NET-1)"),
    ("240.0.0.1", "Reserved"),
    ("224.0.0.251", "Multicast"),
    ("fe80::1", "Link-Local Unicast"),
    ("fd00::1", "Unique-Local"),
    ("2001:db8::1", "Documentation"),
    ("3fff::1", "Documentation"),
    ("ff02::1", "Multicast"),
    ("2001::1", "TEREDO"),                 # Globally Reachable N/A -> special
])
def test_special_purpose(addr, name):
    assert SP.classify(ip(addr)) == name


@pytest.mark.parametrize("addr", [
    "8.8.8.8",
    "192.0.0.9",            # PCP anycast: inside 192.0.0.0/24 but globally reachable
    "192.31.196.1",         # AS112
    "64:ff9b::808:808",     # well-known NAT64 prefix is globally reachable
    "2001:4:112::1",        # AS112-v6
    "2606:4700::1",
])
def test_globally_reachable_is_not_special(addr):
    assert SP.classify(ip(addr)) is None


# --------------------------------------------------------------- routing
def test_routing_longest_prefix_and_moas():
    rt = RoutingTable.from_lines([
        "8.0.0.0\t9\t3356",
        "8.8.8.0\t24\t15169",
        "45.0.0.0\t16\t64500_64501",
        "46.0.0.0/16\t64502,64503",       # pyasn style + AS-set
        "2001:67c:2e8::/48\t3333",
        "47.0.0.0\t16\t1.10",             # asdot
    ])
    assert rt.lookup(ip("8.8.8.8")).origin_asn == 15169
    assert rt.lookup(ip("8.8.9.1")).prefix == "8.0.0.0/9"
    moas = rt.lookup(ip("45.0.1.1"))
    assert moas.origin_asns == (64500, 64501) and moas.origin_asn == 64500
    assert rt.lookup(ip("46.0.0.1")).origin_asns == (64502, 64503)
    assert rt.lookup(ip("47.0.0.1")).origin_asn == 65546
    assert rt.lookup(ip("2001:67c:2e8::5")).origin_asn == 3333
    assert rt.lookup(ip("9.9.9.9")) is None


def test_asnames_strip_country_suffix():
    names = AsNames.from_lines(["15169 GOOGLE - Google LLC, US", "1 LVLT-1 - Level 3 Parent, LLC, US", "bad line"])
    assert names.get(15169) == "GOOGLE - Google LLC"
    assert names.get(1) == "LVLT-1 - Level 3 Parent, LLC"
    assert names.get(None) is None


# ------------------------------------------------------------- delegated
def test_delegated_parse():
    recs = parse_delegated(DELEGATED.splitlines())
    by_start = {str(r.start): r for r in recs}
    assert "46.0.0.0" not in by_start                      # "available" skipped
    ripe = by_start["193.0.0.0"]
    assert (ripe.rir, ripe.country, str(ripe.end), ripe.opaque_id) == ("ripencc", "NL", "193.0.7.255", "opq-ripe-ncc")
    v6 = by_start["2600:1f00::"]
    assert str(v6.end) == "2600:1fff:ffff:ffff:ffff:ffff:ffff:ffff"


def test_delegated_non_power_of_two_count():
    (rec,) = parse_delegated(["ripencc|NL|ipv4|193.0.0.0|768|20200101|allocated|x"])
    assert str(rec.end) == "193.0.2.255"

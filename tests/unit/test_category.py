"""Public Suffix List and the category → subcategory → organisation rules."""

import pytest

from cirrus_ipinfo.core.category import Categorizer, PublicSuffixList
from cirrus_ipinfo.core.enrich import Enricher
from cirrus_ipinfo.core.hashing import changed_layers, enricher_version
from cirrus_ipinfo.core.model import EnrichmentRecord
from cirrus_ipinfo.core.registry.network import NetworkRecord
from tests.conftest import NOW, ip

PSL = PublicSuffixList.default()
CAT = Categorizer.default(asn_types={64500: "Cable/DSL/ISP", 64999: "Content"})


@pytest.mark.parametrize("host,domain", [
    ("csel-123.colorado.edu", "colorado.edu"),
    ("vpn.ua.edu.", "ua.edu"),
    ("www.cs.ox.ac.uk", "ox.ac.uk"),          # multi-label public suffix
    ("host.monash.edu.au", "monash.edu.au"),
    ("ec2-3-5-1-1.compute-1.amazonaws.com", "amazonaws.com"),   # ICANN section only
    ("c-73-1-2-3.hsd1.co.comcast.net", "comcast.net"),
    ("k12.co.us", None),                       # k12.co.us is itself a public suffix
    ("www.k12.co.us", "www.k12.co.us"),
    ("school.k12.co.us", "school.k12.co.us"),
    ("orcid.org", "orcid.org"),
    ("localhost", None),
    (None, None),
])
def test_registrable_domain(host, domain):
    assert PSL.registrable_domain(host) == domain


def test_psl_wildcard_and_exception():
    psl = PublicSuffixList("// ===BEGIN ICANN DOMAINS===\nck\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n")
    assert psl.registrable_domain("a.b.foo.ck") == "b.foo.ck"   # *.ck → foo.ck is a suffix
    assert psl.registrable_domain("x.www.ck") == "www.ck"       # exception
    assert PSL.version  # vendored list records its version


def _rec(**kw) -> EnrichmentRecord:
    base = dict(ip="128.138.1.1", registry_status="resolved", ptr_status="ok")
    return EnrichmentRecord(**(base | kw))


def _net(org):
    return NetworkRecord(ip("128.138.0.0"), ip("128.138.255.255"), "arin", "rdap", org=org)


@pytest.mark.parametrize("kw,expected", [
    # (category, subcategory, org_domain, basis, legacy)
    (dict(ptr="csel-1.colorado.edu", fcrdns=True, network=_net("Regents of the University of Colorado")),
     ("education_research", "university", "colorado.edu", "ptr_suffix", "UNIV")),
    (dict(ptr="lab.ua.edu", fcrdns=True), ("education_research", "university", "ua.edu", "ptr_suffix", "UNIV")),
    (dict(ptr="www.cs.ox.ac.uk", fcrdns=True), ("education_research", "university", "ox.ac.uk", "ptr_suffix", "OTHER")),
    (dict(ptr="host.lanl.gov", fcrdns=True), ("government", "us_government", "lanl.gov", "ptr_suffix", "GOV")),
    (dict(ptr="gw.army.mil", fcrdns=True), ("government", "us_military", "army.mil", "ptr_suffix", "MIL")),
    (dict(ptr="api.orcid.org", fcrdns=True), ("education_research", "research_infrastructure", "orcid.org",
                                              "domain_override", "orcid")),
    (dict(ptr="x.school.k12.co.us", fcrdns=True), ("education_research", "k12", "school.k12.co.us",
                                                  "ptr_suffix", "OTHER")),
    (dict(ptr="c-73.hsd1.co.comcast.net", fcrdns=True, origin_asn=64500),
     ("commercial", "isp_broadband", "comcast.net", "asn_type", "NET")),
    (dict(ptr="host.example.com", fcrdns=True, origin_asn=64999),
     ("cloud", "hosting", "example.com", "asn_type", "COM")),
    (dict(ptr="host.example.com", fcrdns=True), ("unknown", "unclassified", "example.com", "none", "COM")),
    (dict(network=_net("Universidad de Chile")), ("education_research", "university", None, "org_keyword", "-")),
    (dict(ptr_status="nxdomain"), ("unknown", "no_ptr", None, "none", "-")),
    (dict(ptr_status="timeout"), ("unknown", "no_ptr", None, "none", "N/A")),
])
def test_categorize(kw, expected):
    c = CAT.categorize(_rec(**kw))
    assert (c.category, c.subcategory, c.org_domain, c.basis, c.legacy) == expected


def test_internal_ucar_asn_and_domain_but_not_frgp():
    assert CAT.categorize(_rec(origin_asn=194)).category == "internal"
    c = CAT.categorize(_rec(ptr="mlc1.ucar.edu", fcrdns=True))
    assert (c.category, c.subcategory, c.basis, c.legacy) == ("internal", "ncar_ucar", "internal_domain", "NCAR")
    # FRGP (UCAR-run regional R&E network): research_network unless the PTR names a campus
    assert CAT.categorize(_rec(origin_asn=14041)).subcategory == "research_network"
    c = CAT.categorize(_rec(origin_asn=14041, ptr="h.colostate.edu", fcrdns=True))
    assert (c.subcategory, c.org_domain) == ("university", "colostate.edu")


def test_unconfirmed_ptr_is_weak_evidence():
    # A reverse zone owner can claim any name; without FCrDNS it loses to ASN type ...
    c = CAT.categorize(_rec(ptr="fake.whitehouse.gov", fcrdns=False, origin_asn=64500))
    assert (c.category, c.basis) == ("commercial", "asn_type")
    # ... and is only used when nothing else matched, labelled as such.
    c = CAT.categorize(_rec(ptr="host.mit.edu", fcrdns=False))
    assert (c.category, c.basis) == ("education_research", "ptr_suffix_unconfirmed")
    # internal is never granted on an unconfirmed name
    assert CAT.categorize(_rec(ptr="spoof.ucar.edu", fcrdns=False)).category != "internal"


def test_precedence_tor_and_cloud_before_domains():
    assert CAT.categorize(_rec(tor_exit=True, ptr="x.mit.edu", fcrdns=True)).category == "anonymizer"
    c = CAT.categorize(_rec(cloud_provider="aws", ptr="ec2-1.compute-1.amazonaws.com", fcrdns=True))
    assert (c.category, c.subcategory, c.org_domain) == ("cloud", "aws", "amazonaws.com")


def test_special_category():
    c = CAT.categorize(_rec(ip="10.0.0.1", special_purpose="Private-Use", registry_status="not_applicable",
                            ptr_status="skipped"))
    assert (c.category, c.subcategory) == ("special", "private_use")


def test_org_name_prefers_registry_then_as_name():
    assert CAT.categorize(_rec(network=_net("Regents of the University of Colorado"), as_name="CU")).org_name \
        == "Regents of the University of Colorado"
    assert CAT.categorize(_rec(as_name="COMCAST-7922")).org_name == "COMCAST-7922"


def test_rules_change_is_enricher_only():
    a = _rec(category="unknown", enricher_version=enricher_version(1))
    b = _rec(category="unknown", enricher_version=enricher_version(2))
    assert changed_layers(a, b) == ("enricher",)


async def test_enricher_sets_category(local):
    rec = await Enricher(local, now=NOW).enrich("3.5.141.7")
    assert (rec.category, rec.subcategory, rec.category_basis) == ("cloud", "aws", "cloud_range")
    assert rec.enricher_version.endswith(f".c{local.categorizer.version}")
    special = await Enricher(local, now=NOW).enrich("192.168.1.1")
    assert special.category == "special"



# Real cases from the first mlc1 day (2026-11-12): (record fields, expected category, subcategory, basis)
@pytest.mark.parametrize("kw,expected", [
    # Starlink: unconfirmed PTR, but the AS name says what it is
    (dict(ptr="customer.mnlaphl1.isp.starlink.com", fcrdns=False, origin_asn=14593,
          as_name="SPACEX-STARLINK - Space Exploration Technologies Corporation"),
     ("commercial", "isp_broadband", "asn_override")),
    (dict(ptr="customer.mnlaphl1.isp.starlink.com", fcrdns=False, origin_asn=64501,
          as_name="SPACEX-STARLINK - Space Exploration Technologies Corporation"),
     ("commercial", "isp_broadband", "org_keyword")),           # same, without the ASN list
    # scanners/crawlers by confirmed name — beats the hosting ASN they sit in
    (dict(ptr="1.2.3.4.censys-scanner.com", fcrdns=True, origin_asn=398324), ("automated", "security_scanner",
                                                                             "domain_override")),
    (dict(ptr="crawl-66-249-66-1.googlebot.com", fcrdns=True, origin_asn=15169),
     ("automated", "search_engine", "domain_override")),
    (dict(ptr="msnbot-1-2-3-4.search.msn.com", fcrdns=True, origin_asn=8075), ("automated", "search_engine",
                                                                              "ptr_suffix")),
    (dict(ptr="zl-amsc-nl-gp1-wk1b.internet-census.org", fcrdns=True), ("automated", "security_scanner",
                                                                       "domain_override")),
    # big providers without a published-range match
    (dict(origin_asn=8075, ptr_status="nxdomain"), ("cloud", "microsoft", "asn_override")),
    (dict(origin_asn=132203, ptr_status="nxdomain"), ("cloud", "tencent", "asn_override")),
    # RIPE maintainer handle is ignored; the AS description decides
    (dict(network=_net("HYDRA-MNT"), as_name="BANDWIDTH-AS Hydra Communications Ltd", ptr_status="nxdomain"),
     ("commercial", "isp_broadband", "org_keyword")),
    (dict(network=_net("lir-de-3xktechgmbh-1-MNT"), as_name="Drei-K-Tech-GmbH 3xK Tech GmbH", ptr_status="nxdomain"),
     ("commercial", "company", "company_name")),
    (dict(as_name="TC-DATACENTER TC DATACENTER LIMITED", ptr_status="nxdomain"), ("cloud", "hosting", "org_keyword")),
    (dict(as_name="CNCGROUP-SH - China Unicom Shanghai network", ptr_status="nxdomain"),
     ("commercial", "isp_broadband", "org_keyword")),
    (dict(as_name="UNICOM-DongGuan-IDC - China Unicom Guangdong IP network", ptr_status="nxdomain"),
     ("cloud", "hosting", "org_keyword")),                       # an IDC is a data centre, even a telco's
    # hostname tokens describe the line type
    (dict(ptr="mm-1-2-3-4.mgts.dynamic.pppoe.byfly.by", fcrdns=False), ("commercial", "isp_broadband", "ptr_label")),
    (dict(ptr="vps12.trouble-free.net", fcrdns=False), ("cloud", "hosting", "ptr_label")),
    (dict(ptr="1.2.3.4.baremetal.zare.com", fcrdns=False), ("cloud", "hosting", "ptr_label")),
    (dict(as_name="KREDIT-AS LLC VASH KREDIT BANK", ptr_status="nxdomain"), ("commercial", "company", "company_name")),
    (dict(as_name="AS18734 - Operbes, S.A. de C.V.", ptr_status="nxdomain"), ("commercial", "company", "company_name")),
    (dict(as_name="WHITELABELCOLO393 - WhiteLabelColo", ptr_status="nxdomain"), ("cloud", "hosting", "org_keyword")),
    # names that must NOT trip the rules
    (dict(as_name="CSUNET - Colorado State University", ptr_status="nxdomain"),
     ("education_research", "university", "org_keyword")),
    (dict(as_name="BLIX-AS Blix Solutions AS", ptr_status="nxdomain"), ("commercial", "company", "company_name")),
    (dict(as_name="EXAMPLE-AS", ptr_status="nxdomain"), ("unknown", "no_ptr", "none")),
    (dict(network=_net("Regents of the University of Colorado"), as_name="COLORADO - University of Colorado",
          ptr_status="nxdomain"), ("education_research", "university", "org_keyword")),
])
def test_real_cases(kw, expected):
    c = CAT.categorize(_rec(**kw))
    assert (c.category, c.subcategory, c.basis) == expected


def test_org_name_skips_maintainer_handles():
    c = CAT.categorize(_rec(network=_net("HYDRA-MNT"), as_name="BANDWIDTH-AS Hydra Communications Ltd"))
    assert c.org_name == "BANDWIDTH-AS Hydra Communications Ltd"
    assert Categorizer.as_description("GOOGLE - Google LLC") == "Google LLC"
    assert Categorizer.as_description("OVH OVH SAS") == "OVH SAS"



def test_cluster_nodes_are_their_own_subcategory():
    c = CAT.categorize(_rec(ip="128.117.217.72", origin_asn=194, ptr="nwc1w10.k8s.ucar.edu", fcrdns=True))
    assert (c.category, c.subcategory, c.basis) == ("internal", "k8s_node", "k8s_node_ptr")
    c = CAT.categorize(_rec(ip="128.117.215.66", origin_asn=194, ptr_status="nxdomain"))
    assert (c.subcategory, c.basis) == ("k8s_node", "k8s_node_cidr")
    # an unconfirmed node-looking name, or another UCAR host, is a normal internal client
    assert CAT.categorize(_rec(ip="128.117.217.72", origin_asn=194, ptr="nwc1w10.k8s.ucar.edu",
                               fcrdns=False)).subcategory == "ncar_ucar"
    assert CAT.categorize(_rec(ip="128.117.208.134", origin_asn=194, ptr="casper20.hpc.ucar.edu",
                               fcrdns=True)).subcategory == "ncar_ucar"

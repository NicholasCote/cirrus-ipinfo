"""The GDEX (rda-python-metrics ``dssdb.ipinfo``) compatibility block."""

import pytest

from cirrus_ipinfo.core import gdex
from cirrus_ipinfo.core.model import EnrichmentRecord


@pytest.mark.parametrize(("host", "expected"), [
    ("casper20.hpc.ucar.edu", "NCAR"),
    ("www.colorado.edu", "UNIV"),
    ("host.cs.tsinghua.edu.cn", "UNIV"),        # .edu followed by a two-letter country code
    ("ns.noaa.gov", "GOV"),
    ("a.b.army.mil", "MIL"),
    ("x.example.org", "ORG"),
    ("8.8.8.8.google.com", "COM"),               # <ip>.<as_domain> fallback hostnames count too
    ("cpe.example.com.au", "COM"),
    ("c-1-2-3-4.hsd1.co.comcast.net", "NET"),
    ("host.example.de", "OTHER"),
    ("edu.example.de", "OTHER"),                 # needs a leading dot
    (None, "OTHER"),
])
def test_org_type_matches_get_org_type(host, expected):
    assert gdex.org_type(host) == expected


@pytest.mark.parametrize(("name", "expected"), [
    ("Boulder", "Boulder"),
    ("New York", "NewYork"),
    ("São Paulo", "SaoPaulo"),
    ("Zürich", "Zurich"),
    ("Kraków", "Krakow"),
    ("Łódź", "Lodz"),
    ("Tromsø", "Tromso"),
    ("Saint-Étienne", "SaintEtienne"),
    ("Düsseldorf", "Dusseldorf"),
    ("北京", "X"),                                # nothing transliterable → default
    (None, "X"),
    ("", "X"),
])
def test_convert_chars(name, expected):
    assert gdex.convert_chars(name) == expected


@pytest.mark.parametrize(("name", "token"), [
    ("United States", "UNITED.STATES"), ("China", "P.R.CHINA"), ("South Korea", "SOUTH.KOREA"),
    (None, "UNKNOWN"),
])
def test_country_token(name, token):
    assert gdex.country_token(name) == token


def _rec(**kw):
    base = dict(ip="8.8.8.8", registry_status="resolved", geo_country="US", geo_country_name="United States",
                geo_continent="NA", geo_region="California", geo_subdivisions=("California",),
                geo_city="Mountain View", geo_postal="94043", geo_timezone="America/Los_Angeles",
                geo_lat=37.4223, geo_lon=-122.085, ptr="dns.google", fcrdns=True,
                ipinfo_asn=15169, ipinfo_as_name="Google LLC", as_domain="google.com")
    return EnrichmentRecord(**{**base, **kw})


def test_record_shape():
    r = gdex.record(_rec(), stored=True)
    assert r == {
        "ip": "8.8.8.8", "hostname": "dns.google", "lat": 37.4223, "lon": -122.085, "country": "UNITED.STATES",
        "region": "California", "city": "MountainView", "postal": "94043", "timezone": "America/Los_Angeles",
        "org_name": "Google LLC", "org_type": "OTHER", "stat_flag": "A", "bogon": False,
        "ipinfo": {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
                   "country_code": "US", "country": "United States", "continent_code": "NA",
                   "continent": "North America"},
    }
    assert gdex.record(_rec(), stored=False)["stat_flag"] == "M"


def test_hostname_fallbacks():
    r = gdex.record(_rec(ptr=None), stored=True)
    assert (r["hostname"], r["org_type"]) == ("8.8.8.8.google.com", "COM")
    r = gdex.record(_rec(ptr=None, as_domain=None), stored=True)
    assert (r["hostname"], r["org_type"]) == ("8.8.8.8", "-")


def test_missing_geo_uses_gdex_defaults():
    r = gdex.record(_rec(geo_country_name=None, geo_subdivisions=(), geo_city=None, geo_lat=None, geo_lon=None),
                    stored=True)
    assert (r["country"], r["region"], r["city"], r["lat"], r["lon"]) == ("UNKNOWN", None, "X", 0.0, 0.0)


def test_region_is_the_most_specific_subdivision():
    r = gdex.record(_rec(geo_country="GB", geo_country_name="United Kingdom",
                         geo_subdivisions=("England", "Greater London")), stored=True)
    assert (r["country"], r["region"]) == ("UNITED.KINGDOM", "GreaterLondon")


def test_bogon():
    r = gdex.record(EnrichmentRecord(ip="10.1.2.3", registry_status="not_applicable",
                                     special_purpose="Private-Use"), stored=False)
    assert r["bogon"] is True and r["ipinfo"] == {"ip": "10.1.2.3", "bogon": True}
    assert (r["hostname"], r["org_type"], r["country"]) == ("10.1.2.3", "-", "UNKNOWN")


def test_without_ipinfo_org_name_falls_back_to_routing_as_name():
    r = gdex.record(_rec(ipinfo_asn=None, ipinfo_as_name=None, as_domain=None, as_name="GOOGLE - Google LLC"),
                    stored=False)
    assert (r["org_name"], r["ipinfo"]) == ("Google LLC", None)
    assert gdex.record(_rec(ipinfo_as_name=None, as_name="EXAMPLE-AS"), stored=True)["org_name"] is None

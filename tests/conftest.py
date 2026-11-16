"""Shared fixture world for core tests.

A small, consistent universe of real-looking public addresses:

* 193.0.0.0/21, 2001:67c:2e8::/48  RIPE NCC space, resolved from the RPSL dump
* 193.0.0.0-193.0.0.99             a nested non-CIDR assignment (most specific wins)
* 8.8.8.0/24                       ARIN space, resolved over (mocked) RDAP
* 3.5.140.0/22                     AWS (AMAZON + EC2 entries), ARIN
* 185.220.101.0/24                 Tor exit + FireHOL-listed, RIPE dump
* 45.0.0.0/16                      MOAS prefix (two origins), Spamhaus DROP
* 2600:1f18::/32                   AWS IPv6
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest
from mmdb_writer import MMDBWriter
from netaddr import IPSet

from cirrus_ipinfo.core.classify import (
    Classifier,
    parse_aws,
    parse_netset,
    parse_spamhaus_drop,
)
from cirrus_ipinfo.core.localdb import (
    DbipCityReader,
    GeoLite2CityReader,
    IpinfoLiteReader,
    LocalData,
    SourceRef,
)
from cirrus_ipinfo.core.registry.delegated import DelegatedStats
from cirrus_ipinfo.core.registry.rdap import Bootstrap
from cirrus_ipinfo.core.registry.rpsl import RpslDatabase
from cirrus_ipinfo.core.registry.transfers import TransferLog
from cirrus_ipinfo.core.routing import AsNames, RoutingTable
from cirrus_ipinfo.core.special import SpecialPurpose

DATA = Path(__file__).parent / "fixtures" / "data"
NOW = datetime(2026, 11, 13, 2, 0, tzinfo=UTC)

PFX2AS = """\
# CAIDA pfx2as style
193.0.0.0\t21\t3333
8.8.8.0\t24\t15169
3.5.140.0\t22\t16509
185.220.101.0\t24\t208294
45.0.0.0\t16\t64500_64501
2001:67c:2e8::\t48\t3333
2600:1f18::\t32\t16509
"""

ASNAMES = """\
3333 RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre (RIPE NCC), NL
15169 GOOGLE - Google LLC, US
16509 AMAZON-02 - Amazon.com, Inc., US
208294 FIXTURE-RELAYS, DE
64500 FIXTURE-MOAS-A, US
"""

DELEGATED = """\
2|nro|20261112|9|19700101|20261112|+0000
ripencc|*|ipv4|*|4|summary
ripencc|NL|ipv4|193.0.0.0|2048|19930901|assigned|opq-ripe-ncc
ripencc|DE|ipv4|185.220.100.0|1024|20180101|allocated|opq-relays
arin|US|ipv4|8.0.0.0|16777216|19921201|allocated|opq-level3
arin|US|ipv4|3.0.0.0|16777216|19940501|allocated|opq-amazon
arin|US|ipv4|45.0.0.0|65536|20140101|allocated|opq-moas
arin|ZZ|ipv4|46.0.0.0|256|00000000|available|
ripencc|NL|ipv6|2001:67c::|32|20080101|allocated|opq-ripe-ncc
arin|US|ipv6|2600:1f00::|24|20140101|allocated|opq-amazon
"""

AWS = {
    "syncToken": "1", "createDate": "2026-11-13-00-00-00",
    "prefixes": [
        {"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "AMAZON", "network_border_group": "ap-northeast-2"},
        {"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "EC2", "network_border_group": "ap-northeast-2"},
    ],
    "ipv6_prefixes": [
        {"ipv6_prefix": "2600:1f18::/32", "region": "us-east-1", "service": "AMAZON", "network_border_group": "us-east-1"},
    ],
}

TOR = "185.220.101.1\n185.220.101.2\n"
FIREHOL = "# firehol_level1 sample\n0.0.0.0/8\n10.0.0.0/8\n185.220.101.0/24\n192.168.0.0/16\n"
DROP_V4 = (
    '{"cidr":"45.0.0.0/16","sblid":"SBL000001","rir":"arin"}\n'
    '{"type":"metadata","timestamp":1794585404,"size":1,"records":1,"copyright":"x","terms":"y"}\n'
)


def _write_mmdbs(tmp: Path) -> tuple[Path, Path, Path]:
    ii = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="ipinfo_lite")
    for net, rec in [
        ("193.0.0.0/21", {"asn": "AS3333", "as_name": "RIPE NCC", "country_code": "NL", "country": "Netherlands"}),
        ("8.8.8.0/24", {"asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com", "country_code": "US",
                        "country": "United States", "continent_code": "NA", "continent": "North America"}),
        ("3.5.140.0/22", {"asn": "AS16509", "as_name": "Amazon.com, Inc.", "country_code": "KR", "country": "South Korea"}),
        ("185.220.101.0/24", {"asn": "AS208294", "as_name": "Relays", "country_code": "DE", "country": "Germany"}),
        ("2001:67c:2e8::/48", {"asn": "AS3333", "as_name": "RIPE NCC", "country_code": "NL", "country": "Netherlands"}),
    ]:
        ii.insert_network(IPSet([net]), rec)
    ii_path = tmp / "ipinfo_lite.mmdb"
    ii.to_db_file(str(ii_path))

    db = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-City-Lite")
    for net, cc, region, city in [
        ("193.0.0.0/21", "NL", "North Holland", "Amsterdam"),
        ("8.8.8.0/24", "US", "California", "Mountain View"),
        ("3.5.140.0/22", "JP", "Tokyo", "Tokyo"),          # disagrees with IPinfo (KR)
        ("2001:67c:2e8::/48", "NL", "North Holland", "Amsterdam"),
    ]:
        db.insert_network(IPSet([net]), {
            "country": {"iso_code": cc, "names": {"en": cc}},
            "subdivisions": [{"names": {"en": region}}],
            "city": {"names": {"en": city}},
        })
    db_path = tmp / "dbip-city-lite.mmdb"
    db.to_db_file(str(db_path))

    # GeoLite2 City covers 8.8.8.0/24 only, so the other blocks exercise the DB-IP fallback.
    gl = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="GeoLite2-City")
    gl.insert_network(IPSet(["8.8.8.0/24"]), {
        "continent": {"code": "NA", "names": {"en": "North America"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "subdivisions": [{"iso_code": "CA", "names": {"en": "California"}}],
        "city": {"names": {"en": "Mountain View"}},
        "postal": {"code": "94043"},
        "location": {"latitude": 37.4223, "longitude": -122.085, "accuracy_radius": 1000,
                     "time_zone": "America/Los_Angeles"},
    })
    gl_path = tmp / "GeoLite2-City.mmdb"
    gl.to_db_file(str(gl_path))
    return ii_path, db_path, gl_path


def rdap_doc() -> dict:
    return json.loads((DATA / "rdap-arin-8.8.8.0.json").read_text())


@pytest.fixture(scope="session")
def bootstrap() -> Bootstrap:
    return Bootstrap.from_docs(
        json.loads((DATA / "rdap-bootstrap-ipv4.json").read_text()),
        json.loads((DATA / "rdap-bootstrap-ipv6.json").read_text()),
    )


@pytest.fixture(scope="session")
def ripe_db() -> RpslDatabase:
    db = RpslDatabase(default_rir="ripencc")
    with open(DATA / "ripe-sample.db", encoding="latin-1") as fh:
        db.add(fh)
    return db


@pytest.fixture(scope="session")
def local(tmp_path_factory, ripe_db) -> LocalData:
    tmp = tmp_path_factory.mktemp("mmdb")
    ii_path, db_path, gl_path = _write_mmdbs(tmp)
    snap = date(2026, 11, 13)
    return LocalData(
        special=SpecialPurpose.default(),
        routing=RoutingTable.from_lines(PFX2AS.splitlines()),
        asnames=AsNames.from_lines(ASNAMES.splitlines()),
        delegated=DelegatedStats.from_lines(DELEGATED.splitlines()),
        registry_dumps=LocalData.build_registry_index(ripe_db.records()),
        classifier=Classifier(
            cloud=parse_aws(AWS),
            tor_exits=parse_netset(TOR.splitlines()),
            blocklists={
                "firehol_level1": parse_netset(FIREHOL.splitlines()),
                "spamhaus_drop": parse_spamhaus_drop(DROP_V4.splitlines()),
            },
        ),
        transfers=TransferLog([]),
        ipinfo=IpinfoLiteReader(ii_path),
        dbip=DbipCityReader(db_path),
        geolite=GeoLite2CityReader(gl_path),
        snapshots={
            name: SourceRef(name, snap, i + 1)
            for i, name in enumerate(["routeviews_pfx2as", "asnames", "ipinfo_lite", "dbip_city_lite", "geolite2_city",
                                      "aws", "tor_exits", "firehol_level1", "spamhaus_drop",
                                      "iana_special", "delegated", "ripe_db"])
        },
    )


class FakeClock:
    """Deterministic clock/sleep pair for token buckets and backoff."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


def rdap_transport(routes: dict[str, list[httpx.Response] | httpx.Response], calls: list[str]):
    """httpx MockTransport: URL path → response (or queue of responses)."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        for suffix, resp in routes.items():
            if str(request.url).endswith(suffix):
                if isinstance(resp, list):
                    return resp.pop(0) if len(resp) > 1 else resp[0]
                return resp
        return httpx.Response(404, json={"errorCode": 404})

    return httpx.MockTransport(handler)


def ip(s: str):
    return ipaddress.ip_address(s)

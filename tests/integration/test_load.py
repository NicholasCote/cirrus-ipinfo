"""load against a real Postgres 18 (skipped unless IPINFO_TEST_DATABASE_URL is set).

    podman run -d --name ipinfo-pg -e POSTGRES_PASSWORD=pw -p 55432:5432 docker.io/library/postgres:18
    psql: CREATE ROLE ipinfo_owner LOGIN PASSWORD 'owner'; CREATE ROLE ipinfo_writer; CREATE ROLE ipinfo_api;
          CREATE ROLE ipinfo_reader; CREATE DATABASE ipinfo OWNER ipinfo_owner;
    IPINFO_TEST_DATABASE_URL=postgresql://ipinfo_owner:owner@localhost:55432/ipinfo pytest tests/integration

Each test drops and re-creates the ``ipinfo`` schema through the real migration.
"""

import os
from datetime import date, timedelta

import httpx
import pytest

from cirrus_ipinfo.core.dns import PtrResolver
from cirrus_ipinfo.core.enrich import Enricher
from cirrus_ipinfo.core.registry.rdap import RdapClient
from cirrus_ipinfo.core.registry.resolve import RegistryResolver
from cirrus_ipinfo.pipeline.db import connect, load_current, load_network_cache
from cirrus_ipinfo.pipeline.load import load
from cirrus_ipinfo.pipeline.store import LocalStore
from tests.conftest import NOW, FakeClock, rdap_doc, rdap_transport
from tests.unit.test_enrich import FakeDns

URL = os.environ.get("IPINFO_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="IPINFO_TEST_DATABASE_URL not set")

IPS = ["8.8.8.8", "193.0.2.5", "10.0.0.1"]
DAY1 = date(2026, 11, 12)


@pytest.fixture
def db():
    from cirrus_ipinfo.db import migrate
    with connect(URL, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS ipinfo CASCADE")
    migrate.upgrade(url=URL)
    with connect(URL, autocommit=True) as c:
        c.execute("SELECT ipinfo.ensure_observation_partitions(5)")
    with connect(URL) as conn:
        yield conn


def _obs(day, ips=IPS):
    return [{"day": day.isoformat(), "cluster": "mlc1", "tenant": "testtenant", "namespace": "ncote",
             "host": "app.example.edu", "ip": ip, "hits": 3, "hits_4xx": 1, "hits_5xx": 0, "bytes": 99,
             "first_seen": f"{day}T01:00:00+00:00", "last_seen": f"{day}T02:00:00+00:00"} for ip in ips]


async def _run(conn, local, bootstrap, day, now, *, doc=None, budget=None, store=None, ips=IPS):
    cache = await load_network_cache(conn)
    current = load_current(conn, ips)
    conn.commit()
    clock = FakeClock()
    rdap = RdapClient(bootstrap, httpx.AsyncClient(transport=rdap_transport(
        {"/ip/8.8.8.8": httpx.Response(200, json=doc or rdap_doc())}, [])),
        clock=clock, sleep=clock.sleep, now=lambda: now, budget=budget)
    reg = RegistryResolver(cache=cache, now=now, dumps=local.registry_dumps, rdap=rdap, transfers=local.transfers)
    enr = Enricher(local, now=now, registry=reg,
                   dns=PtrResolver(FakeDns(ptr={"8.8.8.8": ["dns.google"]}, fwd={"dns.google": ["8.8.8.8"]})))
    cands = await enr.enrich_many(ips, {ip: v.record for ip, v in current.items()})
    return load(conn, day, cands, current, _obs(day, ips), store, now=now)


def _q(conn, sql, *args):
    return conn.execute(sql, args).fetchall()


async def test_first_day_then_unchanged_then_rerun(db, local, bootstrap, tmp_path):
    store = LocalStore(tmp_path)
    s1 = await _run(db, local, bootstrap, DAY1, NOW, store=store)
    assert s1["new"] == 3 and s1["observations"] == 3 and s1["network_new"] == 2   # rdap + ripe_dump
    assert list((tmp_path / "rdap" / "arin").rglob("*.json"))                      # raw RDAP kept

    row = _q(db, "SELECT category, org_domain, changed_layers, registry_status FROM ipinfo.ip_enrichment "
                 "WHERE ip = '8.8.8.8'")[0]
    assert row[1] == "dns.google" and row[2] == ["initial"] and row[3] == "resolved"
    special = _q(db, "SELECT category, registry_status, network_id FROM ipinfo.ip_enrichment "
                     "WHERE ip = '10.0.0.1'")[0]
    assert special == ("special", "not_applicable", None)

    s2 = await _run(db, local, bootstrap, DAY1 + timedelta(days=1), NOW + timedelta(days=1), store=store)
    assert s2["unchanged"] == 3 and s2.get("new", 0) == 0 and s2["observations"] == 3
    # re-running a day is idempotent
    s2b = await _run(db, local, bootstrap, DAY1 + timedelta(days=1), NOW + timedelta(days=1), store=store)
    assert s2b["unchanged"] == 3
    # ... and a re-run after a rules change replaces that day's version in place, without a new row
    v1 = _q(db, "SELECT id, first_verified_at FROM ipinfo.ip_enrichment WHERE ip = '8.8.8.8'")[0]
    db.execute("UPDATE ipinfo.ip_enrichment SET category = 'unknown', enricher_version = '0.0.0+h2.c1' "
               "WHERE ip = '8.8.8.8'")
    db.commit()
    s1b = await _run(db, local, bootstrap, DAY1, NOW + timedelta(days=1), store=store)
    assert s1b["same_day_replaced"] == 1
    assert _q(db, "SELECT id, first_verified_at FROM ipinfo.ip_enrichment WHERE ip = '8.8.8.8'")[0] == v1
    assert _q(db, "SELECT category FROM ipinfo.ip_enrichment WHERE ip = '8.8.8.8'")[0][0] != 'unknown'
    assert _q(db, "SELECT count(*) FROM ipinfo.ip_enrichment")[0][0] == 3
    assert _q(db, "SELECT count(*), sum(hits) FROM ipinfo.observation")[0] == (6, 18)
    # a re-run without one of the IPs removes that IP's stale row for the day (other days untouched)
    await _run(db, local, bootstrap, DAY1 + timedelta(days=1), NOW + timedelta(days=1), store=store,
               ips=["8.8.8.8", "193.0.2.5"])
    assert _q(db, "SELECT count(*) FROM ipinfo.observation WHERE day = %s", DAY1 + timedelta(days=1))[0][0] == 2
    assert _q(db, "SELECT count(*) FROM ipinfo.observation WHERE day = %s", DAY1)[0][0] == 3
    # the enriched view joins it all together
    v = _q(db, "SELECT org, category, tenant FROM ipinfo.observation_enriched WHERE ip = '8.8.8.8' LIMIT 1")[0]
    assert v[0] == "Google LLC" and v[2] == "testtenant"


async def test_ownership_change_creates_new_versions(db, local, bootstrap):
    await _run(db, local, bootstrap, DAY1, NOW)
    doc = rdap_doc()
    doc["entities"] = [e for e in doc.get("entities", []) if "registrant" not in e.get("roles", [])] + [
        {"objectClassName": "entity", "handle": "NEWCO", "roles": ["registrant"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "New Owner Inc"]]]}]
    later = NOW + timedelta(days=100)              # past the 90-day re-verification age → refetch
    stats = await _run(db, local, bootstrap, later.date(), later, doc=doc)
    assert stats["changed"] == 1 and stats["changed_registry"] == 1 and stats["network_changed"] == 1

    versions = _q(db, "SELECT valid_from, superseded_at IS NOT NULL, changed_layers, org_name "
                      "FROM ipinfo.ip_enrichment WHERE ip = '8.8.8.8' ORDER BY valid_from")
    assert [v[1] for v in versions] == [True, False]
    assert "registry" in versions[1][2] and versions[1][3] == "New Owner Inc"
    nets = _q(db, "SELECT org, superseded_at IS NOT NULL, superseded_by IS NOT NULL FROM ipinfo.network "
                  "WHERE source = 'rdap' ORDER BY id")
    assert nets == [("Google LLC", True, True), ("New Owner Inc", False, False)]
    # the old day's observations still point at the old version
    old = _q(db, "SELECT e.org_name FROM ipinfo.observation o JOIN ipinfo.ip_enrichment e "
                 "ON e.id = o.enrichment_id WHERE o.ip = '8.8.8.8' AND o.day = %s", DAY1)
    assert old == [("Google LLC",)]


async def test_pending_is_filled_in_once(db, local, bootstrap):
    s1 = await _run(db, local, bootstrap, DAY1, NOW, budget=0, ips=["8.8.8.8"])
    assert s1["new"] == 1
    assert _q(db, "SELECT registry_status, network_id FROM ipinfo.ip_enrichment")[0] == ("pending", None)

    s2 = await _run(db, local, bootstrap, DAY1 + timedelta(days=1), NOW + timedelta(days=1), ips=["8.8.8.8"])
    assert s2["pending_filled_in"] == 1 and s2.get("new", 0) == 0
    rows = _q(db, "SELECT registry_status, network_id IS NOT NULL, org_name, valid_from FROM ipinfo.ip_enrichment")
    assert rows == [("resolved", True, "Google LLC", DAY1)]

"""API against a loaded Postgres 18 (skipped unless IPINFO_TEST_DATABASE_URL is set)."""

import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from cirrus_ipinfo.api.app import create_app
from cirrus_ipinfo.api.ondemand import Loaded, OnDemand
from cirrus_ipinfo.core.dns import PtrResolver
from cirrus_ipinfo.pipeline import submissions
from cirrus_ipinfo.pipeline.db import load_current, load_network_cache
from tests.conftest import NOW
from tests.integration.test_load import DAY1, URL, _run, db, pytestmark  # noqa: F401
from tests.unit.test_enrich import FakeDns


def _app(conn, local):
    cache = asyncio.run(load_network_cache(conn))
    conn.commit()
    od = OnDemand(loaded=Loaded(local, cache, local.transfers, 1),
                  dns=PtrResolver(FakeDns(ptr={"193.0.4.20": ["host.ripe.net"]},
                                          fwd={"host.ripe.net": ["193.0.4.20"]})))
    return create_app(URL, od)


def test_api_lookup_history_batch_summary(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(_app(db, local)) as c:
        assert c.get("/healthz").json() == {"ok": True}
        d = c.get("/v1/ip/8.8.8.8").json()
        assert d["registry"]["network"]["org"] == "Google LLC" and d["dns"]["ptr"] == "dns.google"
        assert d["seen"]["requests"] == 3 and d["seen"]["tenants"] == ["testtenant"]
        assert d["version"]["changed_layers"] == ["initial"] and d["attribution"]

        assert c.get("/v1/ip/::ffff:8.8.8.8").json()["ip"] == "8.8.8.8"      # v4-mapped normalised
        assert c.get("/v1/ip/nope").status_code == 400
        nf = c.get("/v1/ip/192.168.1.1/history")
        assert nf.status_code == 404 and nf.json()["detail"]["special_purpose"] == "Private-Use"

        assert len(c.get("/v1/ip/8.8.8.8/history").json()["versions"]) == 1
        lines = c.post("/v1/ip/batch", json={"ips": ["8.8.8.8", "203.0.113.7", "x"]}).text.splitlines()
        assert len(lines) == 3 and '"stored": false' in lines[1] and "error" in lines[2]
        assert c.get("/readyz").json() == {"ok": True, "datasets": 1}

        s = c.get("/v1/summary?days=7").json()
        assert s["last_day"] == DAY1.isoformat() and sum(x["requests"] for x in s["categories"]) == 9
        assert c.get("/").status_code == 200 and "CIRRUS IP info" in c.get("/").text
        assert "/v1/ip/{ip}" in c.get("/openapi.json").json()["paths"]


def test_breakdown_drills_down_and_applications(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(_app(db, local)) as c:
        top = c.get("/v1/breakdown?level=category&days=7").json()
        assert top["requests"] == 9 and sum(r["requests"] for r in top["rows"]) == 9
        cat = next(r["key"] for r in top["rows"] if r["key"] != "special")
        sub = c.get(f"/v1/breakdown?level=subcategory&category={cat}").json()["rows"][0]["key"]
        org = c.get(f"/v1/breakdown?level=organisation&category={cat}&subcategory={sub}").json()["rows"][0]["key"]
        ips = c.get("/v1/breakdown", params={"level": "ip", "category": cat, "subcategory": sub,
                                             "organisation": org, "namespace": "ncote",
                                             "host": "app.example.edu"}).json()
        assert ips["rows"] and all(r["requests"] == 3 for r in ips["rows"])
        assert c.get("/v1/breakdown?level=category&namespace=nope").json()["rows"] == []
        assert c.get("/v1/breakdown?level=bogus").status_code == 422
        apps = c.get("/v1/applications").json()
        assert apps["namespaces"] == [{"namespace": "ncote", "tenant": "testtenant", "requests": 9,
                                       "ingress": {"traefik": 9},
                                       "hosts": [{"host": "app.example.edu", "requests": 9, "ips": 3,
                                                  "ingress": ["traefik"]}]}]
        assert apps["ingresses"] == [{"ingress": "traefik", "requests": 9, "ips": 3, "namespaces": 1}]
        assert apps["clusters"] == [{"cluster": "mlc1", "requests": 9, "ips": 3}]
        assert c.get("/static/cisl-logo.png").status_code == 200 and c.get("/favicon.ico").status_code == 200
        assert c.get("/v1/breakdown?ingress=ingress-nginx").json()["rows"] == []


def test_stored_record_has_full_geo_asinfo_and_gdex_block(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(_app(db, local)) as c:
        d = c.get("/v1/ip/8.8.8.8").json()
        assert d["stored"] is True
        assert d["geo"] == {"country": "US", "country_name": "United States", "continent": "NA",
                            "region": "California", "subdivisions": ["California"], "city": "Mountain View",
                            "postal": "94043", "timezone": "America/Los_Angeles", "latitude": 37.4223,
                            "longitude": -122.085, "accuracy_radius_km": 1000, "source": "geolite2_city"}
        assert d["asinfo"] == {"asn": 15169, "as_name": "Google LLC", "as_domain": "google.com"}
        g = d["gdex"]
        assert (g["ip"], g["hostname"], g["country"], g["region"], g["city"], g["postal"]) == (
            "8.8.8.8", "dns.google", "UNITED.STATES", "California", "MountainView", "94043")
        assert (g["org_name"], g["stat_flag"], g["ipinfo"]["as_domain"]) == ("Google LLC", "A", "google.com")
        assert c.get("/v1/ip/8.8.8.8?view=gdex").json() == g
        assert any("GeoLite2" in a for a in d["attribution"])


def test_unstored_ips_are_computed_on_demand(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(_app(db, local)) as c:
        d = c.get("/v1/ip/193.0.4.20").json()          # RIPE space, never observed
        assert d["stored"] is False and d["version"] is None and "seen" not in d
        assert d["registry"]["status"] == "resolved" and d["registry"]["network"]["rir"] == "ripencc"
        assert (d["dns"]["ptr"], d["dns"]["fcrdns"]) == ("host.ripe.net", True)
        assert d["geo"]["city"] == "Amsterdam" and d["geo"]["source"] == "dbip_city_lite"
        g = d["gdex"]
        assert (g["stat_flag"], g["hostname"], g["org_type"], g["country"], g["region"]) == (
            "M", "host.ripe.net", "NET", "NETHERLANDS", "NorthHolland")
        assert "queued" not in d
        assert c.get("/v1/ip/193.0.4.20/history").status_code == 404

        b = c.get("/v1/ip/10.9.8.7").json()           # special-purpose: answered, flagged as bogon
        assert b["stored"] is False and b["gdex"]["bogon"] is True
        assert b["classification"]["special_purpose"] == "Private-Use"

        lines = [json.loads(x) for x in c.post("/v1/ip/batch?view=gdex", json={
            "ips": ["193.0.4.20", "8.8.8.8", "bad", "::ffff:8.8.8.8"]}).text.splitlines()]
        assert [x.get("stat_flag") for x in lines] == ["M", "A", None, "A"]
        assert lines[2] == {"ip": "bad", "error": "not an IP address"} and lines[3]["ip"] == "8.8.8.8"


def test_on_demand_unavailable_while_loading(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(create_app(URL, OnDemand())) as c:
        assert c.get("/readyz").status_code == 503
        assert c.get("/v1/ip/8.8.8.8").json()["stored"] is True       # stored IPs still served
        r = c.get("/v1/ip/193.0.4.20")
        assert r.status_code == 503 and "unavailable" in r.json()["detail"]["error"]
        line = json.loads(c.post("/v1/ip/batch", json={"ips": ["193.0.4.20"]}).text)
        assert line["stored"] is False and "unavailable" in line["error"]


def _submissions(conn):
    return conn.execute("SELECT host(ip), sources, submit_count, processed_at IS NULL, attempts, last_status "
                        "FROM ipinfo.submission ORDER BY ip").fetchall()


def test_submit_queue_and_nightly_processing(db, local, bootstrap):  # noqa: F811
    asyncio.run(_run(db, local, bootstrap, DAY1, NOW))
    with TestClient(_app(db, local)) as c:
        assert c.get("/v1/ip/193.0.4.20?submit=true&source=gdex").json()["queued"] is True
        assert c.get("/v1/ip/8.8.8.8?submit=true&source=gdex").json()["queued"] is False   # stored, fresh
        assert c.get("/v1/ip/1.2.3.4?submit=true&source=BAD SOURCE").status_code == 422
        lines = [json.loads(x) for x in c.post("/v1/ip/batch", json={
            "ips": ["193.0.4.20", "3.5.141.7"], "submit": True, "source": "gdex"}).text.splitlines()]
        assert [x["queued"] for x in lines] == [True, True]
        r = c.post("/v1/submit", json={"ips": ["3.5.141.7", "8.8.8.8", "10.0.0.9", "nope"], "source": "osdf"})
        assert r.status_code == 202
        assert r.json() == {"received": 4, "queued": 1, "special_purpose": 1, "already_stored": 1,
                            "invalid": ["nope"], "invalid_count": 1}
    db.rollback()
    assert _submissions(db) == [("3.5.141.7", ["gdex", "osdf"], 2, True, 0, None),
                                ("193.0.4.20", ["gdex"], 2, True, 0, None)]

    # the nightly picks pending submissions up with the day's observed IPs
    pending = submissions.pending(db, 100)
    assert sorted(pending) == ["193.0.4.20", "3.5.141.7"]
    db.commit()
    day2 = DAY1 + timedelta(days=1)
    stats = asyncio.run(_run(db, local, bootstrap, day2, NOW + timedelta(days=1),
                                ips=["8.8.8.8", "193.0.4.20", "3.5.141.7"], budget=0))
    assert stats["new"] == 2 and stats["unchanged"] == 1
    # mark() reads the stored records' registry status (what the nightly's candidates carry)
    cands = [SimpleNamespace(record=v.record) for v in load_current(db, pending).values()]
    db.commit()
    assert submissions.mark(db, pending, cands, set()) == {"submitted_resolved": 1, "submitted_retry": 1}
    rows = {r[0]: r for r in _submissions(db)}
    assert rows["193.0.4.20"][3:] == (False, 0, "resolved")
    assert rows["3.5.141.7"][3:] == (True, 1, "pending")   # no RDAP budget: retried next night
    for _ in range(submissions.MAX_ATTEMPTS - 1):
        submissions.mark(db, ["3.5.141.7"], cands, set())
    assert {r[0]: r for r in _submissions(db)}["3.5.141.7"][3:] == (False, submissions.MAX_ATTEMPTS, "pending")

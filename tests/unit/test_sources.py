"""Dataset download helpers (no network)."""

import io
import tarfile

import httpx
import pytest

from cirrus_ipinfo import sources
from cirrus_ipinfo.sources import SOURCES, _missing, _untar_one, fetch


def _tgz(path, members: dict[str, bytes]):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_untar_picks_the_named_member(tmp_path):
    arc = tmp_path / "a.tar.gz"
    _tgz(arc, {"GeoLite2-City_20261113/COPYRIGHT.txt": b"c",
               "GeoLite2-City_20261113/GeoLite2-City.mmdb": b"MMDB"})
    _untar_one(arc, "GeoLite2-City.mmdb", tmp_path / "out.mmdb")
    assert (tmp_path / "out.mmdb").read_bytes() == b"MMDB"
    with pytest.raises(RuntimeError):
        _untar_one(arc, "nope.mmdb", tmp_path / "x")


def test_geolite_needs_both_maxmind_variables(monkeypatch):
    src = next(s for s in SOURCES if s.name == "geolite2_city")
    monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "k")
    assert _missing(src) == ["MAXMIND_ACCOUNT_ID"]
    monkeypatch.setenv("MAXMIND_ACCOUNT_ID", "1")
    assert _missing(src) == []


def test_geolite_download_uses_basic_auth_and_extracts(tmp_path, monkeypatch):
    src = next(s for s in SOURCES if s.name == "geolite2_city")
    monkeypatch.setattr(sources, "SOURCES", [src])
    monkeypatch.setenv("MAXMIND_ACCOUNT_ID", "123")
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "secret")
    arc = tmp_path / "src.tar.gz"
    _tgz(arc, {"GeoLite2-City_1/GeoLite2-City.mmdb": b"MMDB"})
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers.get("authorization"))
        return httpx.Response(200, content=arc.read_bytes())

    real = httpx.Client
    monkeypatch.setattr(sources.httpx, "Client",
                        lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)}))
    logs = []
    [r] = fetch(tmp_path / "data", force=True, log=logs.append)
    assert r.status == "ok" and (tmp_path / "data" / "GeoLite2-City.mmdb").read_bytes() == b"MMDB"
    assert seen == [httpx.BasicAuth("123", "secret")._auth_header]
    assert "secret" not in "".join(logs) and "secret" not in (r.url or "")

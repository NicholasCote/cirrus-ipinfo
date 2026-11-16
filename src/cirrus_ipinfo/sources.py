"""Public datasets: where to download them and under what terms.

URLs checked on 2026-11-13 (HTTP 200). The nightly ``refresh`` job will reuse
this table; ``cirrus-ipinfo fetch`` uses it to fill a local data directory.

Left out on purpose for local runs: the RIPE/APNIC/AFRINIC bulk WHOIS dumps
(several GB; local runs use RDAP instead) and Azure service tags (the URL
changes weekly and has to be scraped from the download page).
"""

from __future__ import annotations

import gzip
import os
import shutil
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

CAIDA = "https://publicdata.caida.org/datasets/routing"


@dataclass(frozen=True)
class Source:
    name: str
    filename: str
    url: str | Callable[[httpx.Client], str]
    license: str
    max_age_hours: float = 20
    gunzip: bool = False
    needs: str | None = None   # environment variable(s) that must be set (e.g. a token), comma-separated
    auth: Callable[[], tuple[str, str]] | None = None   # HTTP basic auth (dropped on cross-host redirects)
    untar: str | None = None   # tar.gz download: extract the member whose name ends with this


def _missing(src: Source) -> list[str]:
    return [v for v in (src.needs or "").split(",") if v and not os.environ.get(v)]


def _caida_latest(family: str) -> Callable[[httpx.Client], str]:
    """Resolve the newest pfx2as file from CAIDA's creation log."""
    def resolve(http: httpx.Client) -> str:
        log = http.get(f"{CAIDA}/{family}/pfx2as-creation.log").raise_for_status().text
        rows = [line.split("\t") for line in log.splitlines() if line and not line.startswith("#")]
        return f"{CAIDA}/{family}/{rows[-1][2].strip()}"
    return resolve


def _dbip_current(http: httpx.Client) -> str:
    """DB-IP publishes monthly; early in a month the new file may not exist yet."""
    now = datetime.now(UTC)
    prev = (now.year - (now.month == 1), 12 if now.month == 1 else now.month - 1)
    for y, m in ((now.year, now.month), prev):
        url = f"https://download.db-ip.com/free/dbip-city-lite-{y}-{m:02d}.mmdb.gz"
        if http.head(url).status_code == 200:
            return url
    raise RuntimeError("no DB-IP City Lite file for this or last month")


def _maxmind_auth() -> tuple[str, str]:
    return os.environ["MAXMIND_ACCOUNT_ID"], os.environ["MAXMIND_LICENSE_KEY"]


def _ipinfo(http: httpx.Client) -> str:
    return f"https://ipinfo.io/data/ipinfo_lite.mmdb?token={os.environ['IPINFO_TOKEN']}"


RIR_STATS = {
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

SOURCES: list[Source] = [
    Source("iana_rdap_bootstrap_v4", "rdap_ipv4.json", "https://data.iana.org/rdap/ipv4.json", "IANA (public)"),
    Source("iana_rdap_bootstrap_v6", "rdap_ipv6.json", "https://data.iana.org/rdap/ipv6.json", "IANA (public)"),
    *[Source(f"delegated_{rir}", f"delegated-{rir}.txt", url, "RIR statistics (public)")
      for rir, url in RIR_STATS.items()],
    Source("transfers_ripencc", "transfers-ripencc.json",
           "https://ftp.ripe.net/pub/stats/ripencc/transfers/transfers_latest.json", "RIPE NCC (public)"),
    Source("routeviews_pfx2as_v4", "pfx2as-v4.txt", _caida_latest("routeviews-prefix2as"),
           "CAIDA RouteViews Prefix2AS (CAIDA AUA, attribution)", gunzip=True),
    Source("routeviews_pfx2as_v6", "pfx2as-v6.txt", _caida_latest("routeviews6-prefix2as"),
           "CAIDA RouteViews Prefix2AS (CAIDA AUA, attribution)", gunzip=True),
    Source("asnames", "asn.txt", "https://ftp.ripe.net/ripe/asnames/asn.txt", "RIPE NCC (public)"),
    Source("aws", "aws.json", "https://ip-ranges.amazonaws.com/ip-ranges.json", "AWS (public)"),
    Source("gcp", "gcp.json", "https://www.gstatic.com/ipranges/cloud.json", "Google (public)"),
    Source("oracle", "oracle.json", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
           "Oracle (public)"),
    Source("cloudflare_v4", "cloudflare-v4.txt", "https://www.cloudflare.com/ips-v4", "Cloudflare (public)"),
    Source("cloudflare_v6", "cloudflare-v6.txt", "https://www.cloudflare.com/ips-v6", "Cloudflare (public)"),
    Source("tor_exits", "tor-exits.txt", "https://check.torproject.org/torbulkexitlist", "Tor Project (public)",
           max_age_hours=2),
    Source("spamhaus_drop_v4", "drop-v4.json", "https://www.spamhaus.org/drop/drop_v4.json",
           "Spamhaus DROP (free, see spamhaus.org/drop/terms)"),
    Source("spamhaus_drop_v6", "drop-v6.json", "https://www.spamhaus.org/drop/drop_v6.json",
           "Spamhaus DROP (free, see spamhaus.org/drop/terms)"),
    Source("firehol_level1", "firehol-level1.netset",
           "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
           "FireHOL (aggregates upstream lists; terms of each list apply)"),
    Source("dbip_city_lite", "dbip-city-lite.mmdb", _dbip_current, "DB-IP City Lite, CC BY 4.0",
           max_age_hours=24 * 7, gunzip=True),
    Source("ipinfo_lite", "ipinfo_lite.mmdb", _ipinfo, "IPinfo Lite, CC BY-SA 4.0", needs="IPINFO_TOKEN"),
    # Updated Tuesdays and Fridays; GeoLite accounts may download 30 times a day. The EULA requires
    # attribution and replacing (and deleting) superseded copies within 30 days.
    Source("geolite2_city", "GeoLite2-City.mmdb",
           "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
           "MaxMind GeoLite2 EULA (attribution; superseded copies deleted within 30 days)",
           max_age_hours=24, needs="MAXMIND_ACCOUNT_ID,MAXMIND_LICENSE_KEY", auth=_maxmind_auth,
           untar="GeoLite2-City.mmdb"),
]


def _untar_one(archive: Path, suffix: str, dest: Path) -> None:
    """Extract the one regular file whose name ends with ``suffix`` (no paths from the archive are used)."""
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar:
            if m.isfile() and (m.name == suffix or m.name.endswith("/" + suffix)):
                src = tar.extractfile(m)
                if src is None:
                    break
                with src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
                return
    raise RuntimeError(f"{suffix} not found in {archive.name}")


def default_data_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(os.environ.get("CIRRUS_IPINFO_DATA", Path(base) / "cirrus-ipinfo"))


@dataclass
class FetchResult:
    source: Source
    path: Path
    url: str | None          # token stripped; None if skipped
    status: str              # ok | fresh | skipped | failed
    error: str | None = None


def fetch(data_dir: Path, *, force: bool = False, log: Callable[[str], None] = print) -> list[FetchResult]:
    data_dir.mkdir(parents=True, exist_ok=True)
    results: list[FetchResult] = []
    with httpx.Client(timeout=120, follow_redirects=True,
                      headers={"User-Agent": "cirrus-ipinfo/0.1 (dataset fetch)"}) as http:
        for src in SOURCES:
            dest = data_dir / src.filename
            if missing := _missing(src):
                log(f"skip   {src.name:24s} (set {', '.join(missing)} to download)")
                results.append(FetchResult(src, dest, None, "skipped", f"{', '.join(missing)} not set"))
                continue
            if not force and dest.exists() and time.time() - dest.stat().st_mtime < src.max_age_hours * 3600:
                log(f"fresh  {src.name:24s} {dest.name}")
                results.append(FetchResult(src, dest, None, "fresh"))
                continue
            url = None
            try:
                url = src.url(http) if callable(src.url) else src.url
                tmp = dest.with_suffix(dest.suffix + ".part")
                with http.stream("GET", url, auth=src.auth() if src.auth else None) as resp:
                    resp.raise_for_status()
                    with open(tmp, "wb") as fh:
                        for chunk in resp.iter_bytes():
                            fh.write(chunk)
                if src.untar:
                    _untar_one(tmp, src.untar, dest)
                    tmp.unlink()
                elif src.gunzip:
                    with gzip.open(tmp, "rb") as gz, open(dest, "wb") as out:
                        shutil.copyfileobj(gz, out)
                    tmp.unlink()
                else:
                    tmp.replace(dest)
                shown = url.split("?token=")[0]
                log(f"ok     {src.name:24s} {dest.stat().st_size / 1e6:8.1f} MB  {shown}")
                results.append(FetchResult(src, dest, shown, "ok"))
            except Exception as exc:   # one bad source shouldn't stop the rest
                msg = str(exc).split("?token=")[0]
                log(f"FAIL   {src.name:24s} {msg}")
                results.append(FetchResult(src, dest, url.split("?token=")[0] if url else None, "failed", msg))
    return results

"""Datasets: refresh (download → S3 snapshot → dataset_snapshot row) and loading into LocalData."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

from ..core.category import Categorizer
from ..core.classify import (
    Classifier,
    CloudTag,
    parse_aws,
    parse_gcp,
    parse_netset,
    parse_oracle,
    parse_spamhaus_drop,
)
from ..core.localdb import DbipCityReader, GeoLite2CityReader, IpinfoLiteReader, LocalData
from ..core.provenance import SourceRef
from ..core.registry.delegated import DelegatedStats
from ..core.registry.rdap import Bootstrap
from ..core.registry.transfers import TransferLog
from ..core.routing import AsNames, RoutingTable
from ..sources import SOURCES, fetch
from .store import Store, put_file

log = logging.getLogger(__name__)


def _log(msg: str) -> None:
    log.info(msg)


def load_local(d: Path, snapshots: dict[str, SourceRef] | None = None,
               ) -> tuple[LocalData, Bootstrap | None, TransferLog | None]:
    """Build the enricher's local layers from a directory of downloaded datasets.

    ``snapshots`` (source name → SourceRef with the dataset_snapshot id) is
    passed by the pipeline; without it (CLI use) file dates are used.
    """
    def have(*names: str) -> list[Path]:
        return [d / n for n in names if (d / n).exists()]

    def lines(*names: str) -> Iterator[str]:
        for p in have(*names):
            with open(p, encoding="utf-8", errors="replace") as fh:
                yield from fh

    def timed(label, fn):
        t = time.perf_counter()
        out = fn()
        _log(f"  loaded {label:22s} {time.perf_counter() - t:5.1f}s")
        return out

    missing = [n for n in ("pfx2as-v4.txt", "asn.txt", "rdap_ipv4.json", "delegated-arin.txt") if not (d / n).exists()]
    if missing:
        _log(f"warning: {', '.join(missing)} missing from {d}; run `cirrus-ipinfo fetch` first")

    local = LocalData()
    if have("pfx2as-v4.txt", "pfx2as-v6.txt"):
        local.routing = timed("routing", lambda: RoutingTable.from_lines(lines("pfx2as-v4.txt", "pfx2as-v6.txt")))
    if have("asn.txt"):
        local.asnames = timed("AS names", lambda: AsNames.from_lines(lines("asn.txt")))
    deleg = [f"delegated-{r}.txt" for r in ("arin", "ripencc", "apnic", "lacnic", "afrinic")]
    if have(*deleg):
        local.delegated = timed("delegations", lambda: DelegatedStats.from_lines(
            *(open(p, encoding="utf-8", errors="replace") for p in have(*deleg))))

    def classifier() -> Classifier:
        cloud = []
        loaders = [("aws.json", parse_aws), ("gcp.json", parse_gcp), ("oracle.json", parse_oracle)]
        for fn, parse in loaders:
            if have(fn):
                cloud += parse(json.loads((d / fn).read_text()))
        cloud += [(n, CloudTag("cloudflare")) for n in parse_netset(lines("cloudflare-v4.txt", "cloudflare-v6.txt"))]
        bl = {}
        if have("drop-v4.json", "drop-v6.json"):
            bl["spamhaus_drop"] = parse_spamhaus_drop(lines("drop-v4.json", "drop-v6.json"))
        if have("firehol-level1.netset"):
            bl["firehol_level1"] = parse_netset(lines("firehol-level1.netset"))
        return Classifier(cloud, parse_netset(lines("tor-exits.txt")), bl)

    local.classifier = timed("cloud/tor/blocklists", classifier)
    if have("ipinfo_lite.mmdb"):
        local.ipinfo = IpinfoLiteReader(d / "ipinfo_lite.mmdb")
    if have("dbip-city-lite.mmdb"):
        local.dbip = DbipCityReader(d / "dbip-city-lite.mmdb")
    if have("GeoLite2-City.mmdb"):
        local.geolite = GeoLite2CityReader(d / "GeoLite2-City.mmdb")
    rules = Path(d / "category-rules.json")
    if rules.exists():   # local override of the packaged rules, handy for experimenting
        local.categorizer = Categorizer(json.loads(rules.read_text()), local.categorizer.psl)
        _log(f"  using category rules from {rules}")

    if snapshots is None:
        snapshots = {s.name: SourceRef(s.name, date.fromtimestamp((d / s.filename).stat().st_mtime),
                                       attribution=s.license)
                     for s in SOURCES if (d / s.filename).exists()}
    local.snapshots = dict(snapshots)

    boot = None
    if have("rdap_ipv4.json", "rdap_ipv6.json"):
        boot = Bootstrap.from_docs(*(json.loads(p.read_text()) for p in have("rdap_ipv4.json", "rdap_ipv6.json")))
    xfer = None
    if have("transfers-ripencc.json"):
        xfer = timed("transfers", lambda: TransferLog.from_docs(json.loads((d / "transfers-ripencc.json").read_text())))
    return local, boot, xfer


# ------------------------------------------------------------------ refresh
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_lines(path: Path) -> int | None:
    if path.suffix == ".mmdb":
        return None
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def refresh(day: date, data_dir: Path, store: Store, conn, *, force: bool = False) -> tuple[dict[str, SourceRef], dict]:
    """Download every source, snapshot it to S3 and record it; return the snapshots for ``day``.

    A source that fails keeps its previous file (if the work dir still has it)
    and its previous dataset_snapshot row is reused. ``conn`` is a psycopg
    connection (writer role).
    """
    results = fetch(data_dir, force=force, log=_log)
    snapshots: dict[str, SourceRef] = {}
    stats = {"ok": 0, "fresh": 0, "failed": [], "skipped": []}
    for r in results:
        src = r.source
        if r.status in ("failed", "skipped"):
            stats[r.status].append(src.name)
        else:
            stats[r.status] += 1
        if r.status in ("ok", "fresh") and r.path.exists():
            row = conn.execute("SELECT id, snapshot_date FROM ipinfo.dataset_snapshot "
                               "WHERE source = %s AND snapshot_date = %s", (src.name, day)).fetchone()
            if row is None or force:
                s3_key = f"snapshots/{day.isoformat()}/{src.filename}"
                uri = put_file(store, s3_key, r.path)
                row = conn.execute(
                    """INSERT INTO ipinfo.dataset_snapshot
                         (source, snapshot_date, fetched_at, source_url, s3_uri, checksum, size_bytes,
                          record_count, license, attribution, upstream_version)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (source, snapshot_date) DO UPDATE SET
                         fetched_at = EXCLUDED.fetched_at, s3_uri = EXCLUDED.s3_uri,
                         checksum = EXCLUDED.checksum, size_bytes = EXCLUDED.size_bytes,
                         record_count = EXCLUDED.record_count
                       RETURNING id, snapshot_date""",
                    (src.name, day, datetime.fromtimestamp(r.path.stat().st_mtime, UTC), r.url or "(cached)",
                     uri, _sha256(r.path), r.path.stat().st_size, _count_lines(r.path), src.license,
                     src.license, None)).fetchone()
            snapshots[src.name] = SourceRef(src.name, row[1], row[0], src.license)
        else:
            # fall back to the newest earlier snapshot, if the file is still here
            # (the work dir is an emptyDir, so normally restore the file from S3).
            row = conn.execute("SELECT id, snapshot_date, s3_uri FROM ipinfo.dataset_snapshot WHERE source = %s "
                               "AND snapshot_date <= %s AND pruned_at IS NULL "
                               "ORDER BY snapshot_date DESC LIMIT 1", (src.name, day)).fetchone()
            if row and not r.path.exists():
                data = store.get(f"snapshots/{row[1].isoformat()}/{src.filename}")
                if data is not None:
                    r.path.write_bytes(data)
            if row and r.path.exists():
                snapshots[src.name] = SourceRef(src.name, row[1], row[0], src.license)
                stats.setdefault("previous_snapshot_used", []).append(src.name)
    conn.commit()
    return snapshots, stats

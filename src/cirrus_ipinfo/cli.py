"""Local command line: try the enricher on your own IP lists, no cluster needed.

    cirrus-ipinfo fetch                         # download public datasets (~250 MB)
    cirrus-ipinfo lookup 8.8.8.8 128.138.1.1    # enrich a few IPs
    cirrus-ipinfo lookup --log access.log --summary
    cirrus-ipinfo lookup --file ips.txt --format csv > out.csv

``--log`` reads Traefik JSON access logs (``ClientHost``), a Loki/logcli
export of them, or any log whose first field is the client IP (common/
combined log format). Each IP is enriched once; request counts are kept so
the summary can show both unique IPs and requests.

Registry lookups go to RDAP (rate-limited per RIR) and are cached in the data
directory, so repeat runs are fast. Nothing is written anywhere else.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import itertools
import json
import pickle
import re
import sys
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import dns.resolver
import httpx

from .core.addr import normalize
from .core.dns import DnsPythonBackend, PtrResolver
from .core.enrich import Enricher
from .core.model import EnrichmentRecord
from .core.registry.rdap import RdapClient
from .core.registry.resolve import InMemoryNetworkCache, RegistryResolver
from .pipeline.datasets import load_local
from .sources import default_data_dir, fetch

COLUMNS = [
    "ip", "requests", "category", "subcategory", "org_domain", "org_name", "legacy_category", "category_basis",
    "ptr", "fcrdns", "ptr_status", "origin_asn", "as_name", "announced_prefix", "geo_country", "geo_region",
    "geo_city", "rir", "registry_status", "registry_source", "network", "netname", "cloud_provider",
    "cloud_region", "cloud_service", "tor_exit", "blocklists", "special_purpose",
]


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ inputs
_IP_TOKEN = re.compile(r"^\[?([0-9A-Fa-f:.]+?)\]?(?::\d+)?$")


def _as_ip(token: str | None) -> str | None:
    if not token:
        return None
    m = _IP_TOKEN.match(token.strip())
    for cand in (token.strip(), m.group(1) if m else None):
        if cand:
            try:
                return str(normalize(cand))
            except ValueError:
                pass
    return None


def ips_from_log(lines: Iterable[str]) -> Iterator[str]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        brace = line.find("{")
        if brace != -1:   # JSON, possibly behind a logcli timestamp/labels prefix
            try:
                doc = json.loads(line[brace:])
                ip = _as_ip(doc.get("ClientHost")) or _as_ip(doc.get("ClientAddr"))
                if ip:
                    yield ip
                    continue
            except (json.JSONDecodeError, AttributeError):
                pass
        ip = _as_ip(line.split()[0])
        if ip:
            yield ip


def ips_from_list(lines: Iterable[str]) -> Iterator[str]:
    for line in lines:
        tok = line.split("#", 1)[0].strip().split(",")[0].strip()
        ip = _as_ip(tok)
        if ip:
            yield ip
        elif tok:
            _log(f"skipping unparseable line: {line.strip()[:80]}")


def _open(path: str):
    return sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")


# ------------------------------------------------------------ RDAP cache
async def _load_cache(path: Path) -> InMemoryNetworkCache:
    cache = InMemoryNetworkCache()
    if path.exists():
        try:
            for item in pickle.loads(path.read_bytes()):
                await cache.put(item)
        except Exception as exc:   # stale format after a code change: start over
            _log(f"ignoring unreadable RDAP cache ({exc})")
    return cache


def _save_cache(cache: InMemoryNetworkCache, path: Path) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(pickle.dumps(list(cache._by_range.values())))
    tmp.replace(path)


# ---------------------------------------------------------------- output
def _row(rec: EnrichmentRecord, requests: int) -> dict:
    n = rec.network
    return {
        **{c: getattr(rec, c, None) for c in COLUMNS},
        "requests": requests,
        "network": " ".join(n.cidrs) if n else None,
        "netname": n.netname if n else None,
        "blocklists": ",".join(rec.blocklists) or None,
        "tor_exit": rec.tor_exit or None,
    }


def _summary(rows: list[dict], top: int) -> str:
    out = []
    total_ips, total_req = len(rows), sum(r["requests"] for r in rows)

    def table(title: str, key, limit: int | None = None):
        ips, req = Counter(), Counter()
        for r in rows:
            k = key(r)
            ips[k] += 1
            req[k] += r["requests"]
        out.append(f"\n{title}\n{'':40s} {'IPs':>9s} {'%':>6s} {'requests':>11s} {'%':>6s}")
        for k, n in itertools.islice(req.most_common(), limit):
            out.append(f"{str(k)[:40]:40s} {ips[k]:9d} {100 * ips[k] / total_ips:5.1f}% "
                       f"{n:11d} {100 * n / max(total_req, 1):5.1f}%")

    out.append(f"{total_ips} unique IPs, {total_req} requests")
    table("category", lambda r: r["category"])
    table("category / subcategory", lambda r: f"{r['category']} / {r['subcategory']}")
    table(f"top {top} organisations (org_domain, else org_name)",
          lambda r: r["org_domain"] or r["org_name"] or "(unknown)", top)
    table("education_research by institution",
          lambda r: r["org_domain"] or r["org_name"] if r["category"] == "education_research" else None, top)
    table("legacy buckets (compare with the existing team report)", lambda r: r["legacy_category"])
    table("category decided by", lambda r: r["category_basis"])
    return "\n".join(out)


# ------------------------------------------------------------------ main
async def _lookup(args: argparse.Namespace) -> int:
    counts: Counter[str] = Counter()
    sources = 0
    for ip in args.ips:
        if (a := _as_ip(ip)):
            counts[a] += 1
            sources += 1
    for f in args.file or []:
        with _open(f) as fh:
            counts.update(ips_from_list(fh))
        sources += 1
    for f in args.log or []:
        with _open(f) as fh:
            counts.update(ips_from_log(fh))
        sources += 1
    if not sources:
        _log("give IPs as arguments, or --file / --log (use - for stdin)")
        return 2
    if not counts:
        _log("no IP addresses found in the input")
        return 1

    d = Path(args.data_dir)
    _log(f"{len(counts)} unique IPs ({sum(counts.values())} requests); loading datasets from {d}")
    local, boot, xfer = load_local(d)
    now = datetime.now(UTC)

    cache_path = d / "rdap-cache.pickle"
    cache = await _load_cache(cache_path)
    async with httpx.AsyncClient(timeout=30) as http:
        rdap = RdapClient(boot, http, budget=args.rdap_budget) if (boot and not args.no_rdap) else None
        registry = RegistryResolver(cache, now, rdap=rdap, transfers=xfer)
        ptr = None
        if not args.no_dns:
            ns = args.nameserver or dns.resolver.Resolver().nameservers
            ptr = PtrResolver(DnsPythonBackend(list(ns), timeout=args.dns_timeout), concurrency=args.concurrency)
        enricher = Enricher(local, now=now, registry=registry, dns=ptr)

        t = time.perf_counter()
        done = 0
        recs: list[EnrichmentRecord] = []
        sem = asyncio.Semaphore(args.concurrency)

        async def one(ip: str) -> EnrichmentRecord:
            nonlocal done
            async with sem:
                rec = await enricher.enrich(ip)
            done += 1
            if sys.stderr.isatty() and (done % 50 == 0 or done == len(counts)):
                print(f"\r  enriched {done}/{len(counts)}", end="", file=sys.stderr, flush=True)
            return rec

        try:
            recs = await asyncio.gather(*(one(ip) for ip in counts))
        finally:
            _save_cache(cache, cache_path)
        if sys.stderr.isatty():
            print(file=sys.stderr)
        stats = dict(rdap.stats) if rdap else {}
        _log(f"  done in {time.perf_counter() - t:.1f}s; RDAP {stats or 'off'}")

    rows = sorted((_row(r, counts[r.ip]) for r in recs), key=lambda r: (-r["requests"], r["ip"]))
    out = sys.stdout
    if args.format == "csv":
        w = csv.DictWriter(out, COLUMNS)
        w.writeheader()
        w.writerows(rows)
    elif args.format == "json":
        for r in rows:
            out.write(json.dumps(r, default=str) + "\n")
    elif not args.summary:
        for r in rows:
            out.write(f"{r['ip']:39s} {r['requests']:>7d}  {r['category']}/{r['subcategory']}  "
                      f"{r['org_domain'] or '-'}  [{r['org_name'] or '-'}]  AS{r['origin_asn'] or '?'} "
                      f"{r['geo_country'] or '--'}  ptr={r['ptr'] or r['ptr_status']}"
                      f"{'' if r['fcrdns'] is not False else ' (unconfirmed)'}  basis={r['category_basis']}\n")
    if args.summary:
        print(_summary(rows, args.top), file=sys.stderr if args.format != "table" else sys.stdout)
    return 0


def _pipeline(args: argparse.Namespace) -> int:
    import logging

    from .pipeline import nightly as nl
    from .pipeline.config import Settings
    from .pipeline.store import open_store

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)   # one line per Loki/RDAP request is too much
    s = Settings()
    day = getattr(args, "date", None) or nl.yesterday()
    if args.cmd == "nightly":
        nl.run_nightly(s, day, skip_collect=args.skip_collect)
    elif args.cmd == "backfill":
        nl.run_backfill(s, args.start, args.end or nl.yesterday())
    elif args.cmd == "refresh":
        nl.stage_refresh(s, open_store(s), day, force=args.force)
    elif args.cmd == "collect":
        store = open_store(s)
        for cluster in args.cluster or s.collect_clusters:
            asyncio.run(nl.stage_collect(s, store, day, cluster))
    elif args.cmd == "sync-tenants":
        nl.stage_sync_tenants(s, open_store(s))
    elif args.cmd == "maintain":
        nl.stage_maintain(s, day)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cirrus-ipinfo", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", default=str(default_data_dir()),
                   help="dataset directory (default: %(default)s, or $CIRRUS_IPINFO_DATA)")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download the public datasets")
    f.add_argument("--force", action="store_true", help="re-download even if fresh")

    mg = sub.add_parser("migrate", help="apply database migrations (uses $IPINFO_DATABASE_URL)")
    mg.add_argument("revision", nargs="?", default="head")
    mg.add_argument("--show", action="store_true", help="print the current revision instead")
    mg.add_argument("--wait", type=int, default=0, metavar="SECONDS", help="retry connecting this long first")

    ap = sub.add_parser("api", help="serve the HTTP API (uses $IPINFO_DATABASE_URL)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)

    lk = sub.add_parser("lookup", help="enrich IPs from arguments, lists or access logs")
    lk.add_argument("ips", nargs="*", help="IP addresses")
    lk.add_argument("--file", action="append", help="file with one IP per line (first CSV column ok); - = stdin")
    lk.add_argument("--log", action="append", help="access log (Traefik JSON, logcli export, CLF); - = stdin")
    lk.add_argument("--format", choices=["table", "csv", "json"], default="table")
    lk.add_argument("--summary", action="store_true", help="print category / organisation breakdowns")
    lk.add_argument("--top", type=int, default=25, help="rows in the organisation tables")
    lk.add_argument("--no-rdap", action="store_true", help="skip registry lookups (org names come from AS names)")
    lk.add_argument("--rdap-budget", type=int, default=5000, help="max RDAP requests this run")
    lk.add_argument("--no-dns", action="store_true", help="skip PTR lookups (most categories need them)")
    lk.add_argument("--nameserver", action="append", help="DNS server (default: system resolvers)")
    lk.add_argument("--dns-timeout", type=float, default=3.0)
    lk.add_argument("--concurrency", type=int, default=64)

    def day_arg(sp):
        sp.add_argument("--date", type=date.fromisoformat, default=None, help="data day (UTC), default yesterday")

    nt = sub.add_parser("nightly", help="run every pipeline stage for one day (mlc1)")
    day_arg(nt)
    nt.add_argument("--skip-collect", action="store_true", help="reuse the collected files already in S3")
    rf = sub.add_parser("refresh", help="download datasets, snapshot them to S3, record them")
    day_arg(rf)
    rf.add_argument("--force", action="store_true")
    co = sub.add_parser("collect", help="read one cluster-day of Traefik logs from Loki into S3")
    day_arg(co)
    co.add_argument("--cluster", action="append", help="default: $IPINFO_COLLECT_CLUSTERS")
    bf = sub.add_parser("backfill", help="collect + enrich + load a range of past days (latest datasets)")
    bf.add_argument("--from", dest="start", type=date.fromisoformat, required=True)
    bf.add_argument("--to", dest="end", type=date.fromisoformat, default=None, help="default: yesterday")
    sub.add_parser("sync-tenants", help="publish this cluster's namespace → tenant map to S3")
    mt = sub.add_parser("maintain", help="create/drop observation partitions")
    day_arg(mt)

    args = p.parse_args(argv)
    if args.cmd in ("nightly", "refresh", "collect", "sync-tenants", "maintain", "backfill"):
        return _pipeline(args)
    if args.cmd == "api":
        import uvicorn
        uvicorn.run("cirrus_ipinfo.api.app:app", host=args.host, port=args.port, proxy_headers=True,
                    forwarded_allow_ips="*", access_log=False)
        return 0
    if args.cmd == "fetch":
        fetch(Path(args.data_dir), force=args.force, log=_log)
        return 0
    if args.cmd == "migrate":
        from .db import migrate
        if args.wait:
            migrate.wait_for_database(args.wait)
        migrate.current() if args.show else migrate.upgrade(args.revision)
        return 0
    return asyncio.run(_lookup(args))


if __name__ == "__main__":
    sys.exit(main())

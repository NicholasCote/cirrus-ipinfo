"""On-demand enrichment for IPs the database hasn't stored (DESIGN.md §4.7).

The API keeps the nightly run's local datasets in memory (routing, AS names,
delegations, cloud/Tor/blocklists, IPinfo Lite, GeoLite2/DB-IP) plus the
``network`` table as a registry cache. An unstored IP is enriched from those and
a live PTR lookup. RDAP is never called and nothing is written: the result is
marked ``stored: false``. Submitting the IP queues it for the nightly run, which
stores a full, versioned record.

Datasets come from the newest S3 snapshots the nightly ``refresh`` recorded.
Every hour the API checks for a newer snapshot and, if there is one, loads it
into a fresh directory and swaps it in (MMDB files are memory-mapped, so a
loaded directory is never overwritten).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import dns.resolver

from ..core.dns import DnsPythonBackend, PtrResolver
from ..core.enrich import Enricher
from ..core.localdb import LocalData
from ..core.model import EnrichmentRecord
from ..core.registry.resolve import InMemoryNetworkCache, RegistryResolver
from ..core.registry.transfers import TransferLog

log = logging.getLogger(__name__)


@dataclass
class Loaded:
    local: LocalData
    cache: InMemoryNetworkCache
    transfers: TransferLog | None
    snapshot_marker: int | None   # max(dataset_snapshot.id) when loaded
    directory: Path | None = None


class OnDemand:
    def __init__(self, *, settings=None, loaded: Loaded | None = None, dns: PtrResolver | None = None,
                 reload_seconds: float = 3600):
        self.settings = settings
        self.loaded = loaded
        self.error: str | None = None
        self.reload_seconds = reload_seconds
        self._task: asyncio.Task | None = None
        self._generation = 0
        if dns is None and settings is not None:
            ns = list(settings.nameservers) or dns_resolver_nameservers()
            dns = PtrResolver(DnsPythonBackend(ns, timeout=settings.dns_timeout), concurrency=settings.concurrency)
        self.dns = dns

    @property
    def ready(self) -> bool:
        return self.loaded is not None

    # ------------------------------------------------------------ loading
    def _marker(self) -> int | None:
        from ..pipeline.db import connect
        with connect(self.settings.database_url) as conn:
            return conn.execute("SELECT max(id) FROM ipinfo.dataset_snapshot").fetchone()[0]

    def _load_blocking(self, marker: int | None) -> Loaded:
        from ..pipeline.datasets import load_local
        from ..pipeline.db import connect, load_network_cache
        from ..pipeline.nightly import restore_latest_snapshots
        from ..pipeline.store import open_store

        s = self.settings
        self._generation += 1
        d = s.work_dir / f"api-datasets-{self._generation}"
        shutil.rmtree(d, ignore_errors=True)
        snapshots = restore_latest_snapshots(s, open_store(s), dest=d)
        local, _boot, xfer = load_local(d, snapshots)
        with connect(s.database_url) as conn:
            cache = asyncio.run(load_network_cache(conn))
        return Loaded(local, cache, xfer, marker, d)

    async def _refresh(self) -> None:
        marker = await asyncio.to_thread(self._marker)
        if self.loaded is not None and marker == self.loaded.snapshot_marker:
            return
        new = await asyncio.to_thread(self._load_blocking, marker)
        old, self.loaded, self.error = self.loaded, new, None
        log.info("on-demand datasets loaded (snapshot marker %s, %d sources)", marker, len(new.local.snapshots))
        if old is not None and old.directory is not None:
            # Lookups already running keep their reference to the old LocalData; the mmap'd
            # files stay readable after unlink on Linux.
            shutil.rmtree(old.directory, ignore_errors=True)

    async def _run(self) -> None:
        delay = 30.0
        while True:
            try:
                await self._refresh()
                await asyncio.sleep(self.reload_seconds)
                delay = 30.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:   # keep serving the old data; retry with backoff
                self.error = f"{type(exc).__name__}: {exc}"
                log.error("on-demand dataset load failed: %s", self.error)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.reload_seconds)

    def start(self) -> None:
        if self.settings is not None and self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------ lookups
    def enricher(self) -> Enricher:
        if self.loaded is None:
            raise RuntimeError("on-demand datasets are still loading")
        now = datetime.now(UTC)
        ld = self.loaded
        return Enricher(ld.local, now=now, dns=self.dns,
                        registry=RegistryResolver(ld.cache, now, rdap=None, transfers=ld.transfers))

    async def enrich(self, ip: str, enricher: Enricher | None = None) -> EnrichmentRecord:
        return await (enricher or self.enricher()).enrich(ip)


def dns_resolver_nameservers() -> list[str]:
    return list(dns.resolver.Resolver().nameservers)

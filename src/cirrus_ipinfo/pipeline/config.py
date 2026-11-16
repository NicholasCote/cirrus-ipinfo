"""Runtime settings, all from environment variables (set by the k8s manifests)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

CLUSTERS = ("mlc1", "nwc1")

# Ingress controllers whose access logs are collected. The k8s-monitoring chart
# labels pod logs with cluster/namespace/container; "{cluster}" is substituted.
DEFAULT_LOG_SOURCES = [
    {"name": "traefik-external", "format": "traefik",
     "selector": '{cluster="{cluster}", namespace="traefik", container="traefik-external"}'},
    {"name": "traefik-internal", "format": "traefik",
     "selector": '{cluster="{cluster}", namespace="traefik", container="traefik-internal"}'},
    # ingress-nginx runs one controller per class; split by pod name (structured metadata `pod`)
    {"name": "nginx-external", "format": "nginx",
     "selector": '{cluster="{cluster}", namespace="ingress-nginx"} | pod=~".*external.*"'},
    {"name": "nginx-internal", "format": "nginx",
     "selector": '{cluster="{cluster}", namespace="ingress-nginx"} | pod!~".*external.*"'},
]


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


@dataclass
class Settings:
    cluster: str = field(default_factory=lambda: _env("IPINFO_CLUSTER", "mlc1"))
    collect_clusters: tuple[str, ...] = field(
        default_factory=lambda: tuple((_env("IPINFO_COLLECT_CLUSTERS", ",".join(CLUSTERS)) or "").split(",")))
    sync_tenants: bool = field(default_factory=lambda: _env("IPINFO_SYNC_TENANTS", "true").lower() == "true")
    # "mlc1=10.0.0.0/16,10.96.0.0/12;nwc1=..." → in-cluster networks dropped by collect
    exclude_cidrs: dict[str, tuple[str, ...]] = field(default_factory=lambda: {
        c.split("=", 1)[0].strip(): tuple(x.strip() for x in c.split("=", 1)[1].split(",") if x.strip())
        for c in (_env("IPINFO_EXCLUDE_CIDRS", "") or "").split(";") if "=" in c})
    work_dir: Path = field(default_factory=lambda: Path(_env("IPINFO_WORK_DIR", "/tmp/cirrus-ipinfo")))

    # object store (ExternalSecret ipinfo-s3 renders these)
    s3_bucket: str | None = field(default_factory=lambda: _env("S3_BUCKET"))
    s3_endpoint: str | None = field(default_factory=lambda: _env("AWS_ENDPOINT_URL_S3"))
    s3_prefix: str = field(default_factory=lambda: _env("S3_PREFIX", ""))   # key prefix inside the bucket
    local_store: str | None = field(default_factory=lambda: _env("IPINFO_LOCAL_STORE"))  # dev/tests

    # Grafana → Loki datasource proxy
    grafana_url: str = field(default_factory=lambda: _env("GRAFANA_URL", "https://grafana.k8s.ucar.edu"))
    grafana_token: str | None = field(default_factory=lambda: _env("GRAFANA_TOKEN"))
    loki_datasource_uid: str | None = field(default_factory=lambda: _env("LOKI_DATASOURCE_UID"))
    log_sources: list = field(default_factory=lambda: json.loads(_env("IPINFO_LOG_SOURCES", "") or "null")
                              or DEFAULT_LOG_SOURCES)
    # category/subcategory pairs whose IPs are dropped before load (cluster nodes talking to themselves)
    drop_categories: frozenset = field(default_factory=lambda: frozenset(
        x.strip() for x in (_env("IPINFO_DROP_CATEGORIES", "internal/k8s_node") or "").split(",") if x.strip()))

    # enrichment
    rdap_budget: int = field(default_factory=lambda: int(_env("RDAP_BUDGET", "5000")))
    nameservers: tuple[str, ...] = field(
        default_factory=lambda: tuple(filter(None, (_env("DNS_NAMESERVERS", "") or "").split(","))))
    dns_timeout: float = field(default_factory=lambda: float(_env("DNS_TIMEOUT", "2.0")))
    concurrency: int = field(default_factory=lambda: int(_env("ENRICH_CONCURRENCY", "64")))
    # submitted IPs (POST /v1/submit) enriched per nightly run, oldest first
    submit_max: int = field(default_factory=lambda: int(_env("IPINFO_SUBMIT_MAX", "20000")))

    # database (CNPG secret uri)
    database_url: str | None = field(default_factory=lambda: _env("IPINFO_DATABASE_URL"))

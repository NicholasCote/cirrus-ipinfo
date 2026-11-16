"""Namespace → Capsule tenant map for one cluster.

``sync-tenants`` runs in every cluster (it's the only job nwc1 runs). It lists
namespaces through the in-cluster API (ClusterRole: get/list namespaces) and
writes ``tenants/cluster=<c>/namespaces.json`` to the bucket. ``collect`` on
mlc1 reads those files to attribute each request to a tenant.

Tenant resolution:
* namespace has ``capsule.clastix.io/tenant`` → that tenant
* namespace exists but has no tenant label → ``_platform`` (traefik, openbao, …)
* namespace unknown / request matched no router → ``_unmapped``
"""

from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import httpx

TENANT_LABEL = "capsule.clastix.io/tenant"
PLATFORM = "_platform"
UNMAPPED = "_unmapped"
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def key(cluster: str) -> str:
    return f"tenants/cluster={cluster}/namespaces.json"


def list_namespaces(api: str = "https://kubernetes.default.svc", sa_dir: Path = SA_DIR) -> dict[str, str | None]:
    token = (sa_dir / "token").read_text().strip()
    ctx = ssl.create_default_context(cafile=str(sa_dir / "ca.crt"))
    out: dict[str, str | None] = {}
    cont = None
    with httpx.Client(verify=ctx, headers={"Authorization": f"Bearer {token}"}, timeout=30) as http:
        while True:
            params = {"limit": "500", **({"continue": cont} if cont else {})}
            body = http.get(f"{api}/api/v1/namespaces", params=params).raise_for_status().json()
            for ns in body.get("items", []):
                md = ns["metadata"]
                out[md["name"]] = (md.get("labels") or {}).get(TENANT_LABEL)
            cont = body.get("metadata", {}).get("continue")
            if not cont:
                return out


def document(cluster: str, namespaces: dict[str, str | None]) -> bytes:
    return json.dumps({"cluster": cluster, "generated_at": datetime.now(UTC).isoformat(),
                       "namespaces": dict(sorted(namespaces.items()))}, indent=1).encode()


class TenantMap:
    def __init__(self, namespaces: dict[str, str | None]):
        self.namespaces = namespaces
        # longest first, so "ncote-db" wins over "ncote" when parsing router names
        self._by_len = sorted(namespaces, key=len, reverse=True)

    @classmethod
    def from_document(cls, data: bytes | None) -> TenantMap:
        return cls(json.loads(data)["namespaces"] if data else {})

    def tenant(self, namespace: str | None) -> str:
        if not namespace or namespace not in self.namespaces:
            return UNMAPPED
        return self.namespaces[namespace] or PLATFORM

    def namespace_of(self, *, ingress_namespace: str, service: str, router: str) -> str | None:
        """Which namespace served the request.

        Traefik names (provider ``kubernetes`` / ``kubernetescrd``):
            ServiceName  <namespace>-<service>-<port>@kubernetes
            RouterName   <entrypoint>-<namespace>-<ingress>-<host…>@kubernetes
        ingress-nginx:
            upstream     <namespace>-<service>-<port>      (passed as service, "@nginx")
        Namespaces can contain dashes, so the name is matched against the
        cluster's real namespaces, longest first.
        """
        if ingress_namespace:
            return ingress_namespace
        for name, strip_entrypoint in ((service, False), (router, True)):
            base, _, provider = name.partition("@")
            # Traefik: <ns>-<svc>-<port>@kubernetes[crd]. ingress-nginx upstreams use the same
            # <ns>-<svc>-<port> shape (tagged @nginx, or untagged from a JSON log format).
            if provider and not provider.startswith("kubernetes") and provider != "nginx":
                continue
            if not base or base == "upstream-default-backend":
                continue
            if strip_entrypoint:
                base = base.partition("-")[2]
            for ns in self._by_len:
                if base.startswith(ns + "-"):
                    return ns
        return None

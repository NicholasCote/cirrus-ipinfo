"""Object storage: S3 (Ceph RGW) in the cluster, a plain directory for dev/tests.

Layout (DESIGN.md §4.10):
    snapshots/<date>/<file>                  raw datasets as downloaded
    tenants/cluster=<c>/namespaces.json      namespace → Capsule tenant (sync-tenants)
    collected/day=<D>/cluster=<c>/observations.jsonl.gz
    enrich/day=<D>/records.jsonl.gz
    rdap/<rir>/<handle>/<fetched_at>.json    raw RDAP answers (kept forever)
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Protocol


class Store(Protocol):
    def put(self, key: str, data: bytes) -> str: ...
    def get(self, key: str) -> bytes | None: ...
    def exists(self, key: str) -> bool: ...
    def uri(self, key: str) -> str: ...


class LocalStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def uri(self, key: str) -> str:
        return f"file://{self.root / key}"

    def put(self, key: str, data: bytes) -> str:
        p = self.root / key
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(p)
        return self.uri(key)

    def get(self, key: str) -> bytes | None:
        p = self.root / key
        return p.read_bytes() if p.exists() else None

    def exists(self, key: str) -> bool:
        return (self.root / key).exists()


class S3Store:
    """boto3 picks up AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_ENDPOINT_URL_S3."""

    def __init__(self, bucket: str, endpoint: str | None = None, prefix: str = ""):
        import boto3
        from botocore.config import Config

        self.bucket = bucket
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        self._s3 = boto3.client("s3", endpoint_url=endpoint,
                                config=Config(s3={"addressing_style": "path"}, retries={"mode": "standard"}))

    def uri(self, key: str) -> str:
        return f"s3://{self.bucket}/{self.prefix}{key}"

    def put(self, key: str, data: bytes) -> str:
        self._s3.put_object(Bucket=self.bucket, Key=self.prefix + key, Body=data)
        return self.uri(key)

    def put_file(self, key: str, path: Path) -> str:
        self._s3.upload_file(str(path), self.bucket, self.prefix + key)
        return self.uri(key)

    def get(self, key: str) -> bytes | None:
        try:
            return self._s3.get_object(Bucket=self.bucket, Key=self.prefix + key)["Body"].read()
        except self._s3.exceptions.NoSuchKey:
            return None

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self.prefix + key)
            return True
        except ClientError:
            return False


def open_store(settings) -> Store:
    if settings.local_store:
        return LocalStore(settings.local_store)
    if not settings.s3_bucket:
        raise RuntimeError("set S3_BUCKET (or IPINFO_LOCAL_STORE for a local directory)")
    return S3Store(settings.s3_bucket, settings.s3_endpoint, settings.s3_prefix)


def put_file(store: Store, key: str, path: Path) -> str:
    if hasattr(store, "put_file"):
        return store.put_file(key, path)
    return store.put(key, path.read_bytes())


def dump_jsonl_gz(rows: Iterable[dict]) -> bytes:
    body = "".join(json.dumps(r, default=str, separators=(",", ":")) + "\n" for r in rows)
    return gzip.compress(body.encode(), mtime=0)


def load_jsonl_gz(data: bytes) -> Iterator[dict]:
    for line in gzip.decompress(data).decode().splitlines():
        if line:
            yield json.loads(line)

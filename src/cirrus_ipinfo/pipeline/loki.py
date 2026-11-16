"""Read Traefik access logs from Loki through Grafana's datasource proxy.

Loki itself isn't exposed outside the cluster, but Grafana already has it as
a datasource, so we query
``{GRAFANA_URL}/api/datasources/proxy/uid/{uid}/loki/api/v1/query_range``
with a Grafana service-account token (Viewer role in the org that owns the
Loki datasource is enough).

Loki caps each response (``max_entries_limit_per_query``, 5000 by default),
so a day is read in windows and paginated forward by timestamp. Entries that
share the boundary timestamp are de-duplicated.

LogQL does the field extraction server-side and returns one compact
tab-separated line per request, roughly 10x less transfer than raw JSON.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

_ALIASES = ("client", "host", "svc", "router", "ingns", "status", "size")

# Traefik JSON access log (--accesslog.format=json) → our seven columns.
TRAEFIK_FIELDS = {"client": "ClientHost", "host": "RequestHost", "svc": "ServiceName", "router": "RouterName",
                  "ingns": "KubernetesIngressNamespace", "status": "DownstreamStatus",
                  "size": "DownstreamContentSize"}

# ingress-nginx's default log format (log-format-upstream), per the ingress-nginx docs:
#   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer"
#   "$http_user_agent" $request_length $request_time [$proxy_upstream_name] ...
# It has no $host, so the "application" is the upstream (<namespace>-<service>-<port>).
_NGINX_RE = (r'^(?P<client>\S+) - \S+ \[[^\]]+\] "[^"]*" (?P<status>\d{3}) (?P<size>\d+) "[^"]*" "[^"]*" '
             r'\d+ \S+ \[(?P<upstream>[^\]]*)\]')


@dataclass(frozen=True)
class LogSource:
    """One ingress controller's access logs in Loki.

    ``format``: ``traefik`` (JSON), ``nginx`` (ingress-nginx default text format) or
    ``json`` (any JSON format; ``fields`` maps our columns to its keys, e.g. for an
    ingress-nginx ``log-format-escape-json`` setup).
    """

    name: str
    selector: str                      # LogQL stream selector; "{cluster}" is substituted
    format: str = "traefik"
    fields: dict | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "LogSource":
        return cls(d["name"], d["selector"], d.get("format", "traefik"), d.get("fields"))

    def query(self, cluster: str) -> str:
        sel = self.selector.replace("{cluster}", cluster)
        fmt = "\\t".join("{{." + a + "}}" for a in _ALIASES)
        if self.format == "nginx":
            # host := upstream (no $host in the default format); svc gets an @nginx provider tag
            return (f"{sel} |~ `^\\S+ - \\S+ \\[` | regexp `{_NGINX_RE}` "
                    f'| line_format "{{{{.client}}}}\\t{{{{.upstream}}}}\\t{{{{.upstream}}}}@nginx\\t\\t\\t'
                    f'{{{{.status}}}}\\t{{{{.size}}}}"')
        fields = TRAEFIK_FIELDS if self.format == "traefik" else (self.fields or {})
        missing = [a for a in ("client", "status") if a not in fields]
        if missing:
            raise ValueError(f"log source {self.name}: fields needs {missing}")
        extract = ", ".join(f'{a}="{fields[a]}"' for a in _ALIASES if a in fields)
        # columns this format doesn't have render as empty strings
        fmt = "\\t".join(("{{." + a + "}}") if a in fields else "" for a in _ALIASES)
        line_filter = f'|= "{fields["client"]}" ' if self.format == "traefik" else ""
        return f'{sel} {line_filter}| json {extract} | __error__="" | line_format "{fmt}"'


@dataclass(frozen=True)
class AccessEntry:
    ts: datetime
    client: str
    host: str
    service: str
    router: str
    ingress_namespace: str
    status: int
    size: int

    @classmethod
    def parse(cls, ts_ns: str, line: str) -> AccessEntry | None:
        parts = line.split("\t")
        if len(parts) != len(_ALIASES) or not parts[0]:
            return None

        def num(s: str) -> int:
            try:
                return int(float(s))
            except ValueError:
                return 0

        ts = datetime.fromtimestamp(int(ts_ns) / 1e9, UTC)
        return cls(ts, parts[0], parts[1].lower(), parts[2], parts[3], parts[4], num(parts[5]), num(parts[6]))


class LokiError(RuntimeError):
    pass


class GrafanaLoki:
    def __init__(self, http: httpx.AsyncClient, grafana_url: str, datasource_uid: str, token: str | None,
                 *, page_limit: int = 5000, window: timedelta = timedelta(hours=1)):
        self.http = http
        self.base = f"{grafana_url.rstrip('/')}/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1"
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.page_limit = page_limit
        self.window = window
        self.stats = {"requests": 0, "entries": 0}

    async def _get(self, params: dict) -> dict:
        for attempt in range(5):
            self.stats["requests"] += 1
            resp = await self.http.get(f"{self.base}/query_range", params=params, headers=self.headers)
            if resp.status_code in (429, 502, 503, 504):
                await asyncio.sleep(min(60, 2 ** attempt * 2))
                continue
            if resp.status_code != 200:
                raise LokiError(f"Loki query failed: HTTP {resp.status_code}: {resp.text[:300]}")
            body = resp.json()
            if body.get("status") != "success":
                raise LokiError(f"Loki query failed: {str(body)[:300]}")
            return body["data"]
        raise LokiError("Loki query kept failing (rate limited / unavailable)")

    async def entries(self, query: str, start: datetime, end: datetime) -> AsyncIterator[tuple[str, str]]:
        """Yield ``(ts_ns, line)`` for every entry in ``[start, end)``, oldest first."""
        win_start = start
        while win_start < end:
            win_end = min(win_start + self.window, end)
            cursor = int(win_start.timestamp() * 1e9)
            stop = int(win_end.timestamp() * 1e9)
            seen_at_cursor: set[tuple[str, str]] = set()
            while cursor < stop:
                data = await self._get({"query": query, "start": str(cursor), "end": str(stop),
                                        "limit": str(self.page_limit), "direction": "forward"})
                page = sorted(
                    ((int(ts), line, repr(sorted(s.get("stream", {}).items())))
                     for s in data.get("result", []) for ts, line in s.get("values", [])),
                    key=lambda e: e[0])
                new = 0
                for ts, line, labels in page:
                    if ts == cursor and (labels, line) in seen_at_cursor:
                        continue
                    if ts != cursor:
                        cursor, seen_at_cursor = ts, set()
                    seen_at_cursor.add((labels, line))
                    new += 1
                    self.stats["entries"] += 1
                    yield str(ts), line
                if len(page) < self.page_limit:
                    break
                if new == 0:
                    # A full page of entries at one nanosecond: skip past it rather than loop.
                    cursor += 1
                    seen_at_cursor = set()
            win_start = win_end

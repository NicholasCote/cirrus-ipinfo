"""IPs submitted through the API (``POST /v1/submit``, or ``submit`` on a lookup).

The nightly run enriches pending submissions together with the day's observed
IPs and stores them as ordinary versions (without observations). An IP whose
registry lookup is still ``pending`` afterwards (RDAP budget used up) stays
queued and is retried the next night, up to ``MAX_ATTEMPTS`` runs; the load's
pending fill-in completes its version in place.
"""

from __future__ import annotations

from collections import Counter

import psycopg

from ..core.enrich import Candidate

MAX_ATTEMPTS = 7   # matches load.FILL_IN_WINDOW: after a week a pending record is final


def pending(conn: psycopg.Connection, limit: int) -> list[str]:
    if limit <= 0:
        return []
    rows = conn.execute("SELECT host(ip) FROM ipinfo.submission WHERE processed_at IS NULL "
                        "ORDER BY first_submitted_at, ip LIMIT %s", (limit,)).fetchall()
    return [r[0] for r in rows]


def mark(conn: psycopg.Connection, ips: list[str], candidates: list[Candidate], dropped: set[str]) -> dict:
    by_ip = {c.record.ip: c.record for c in candidates}
    done: dict[str, list[str]] = {}
    retry = []
    for ip in ips:
        rec = by_ip.get(ip)
        if ip in dropped:
            status = "dropped"
        elif rec is None:
            status = "missing"
        elif rec.special_purpose:
            status = "special"
        else:
            status = rec.registry_status
        if status == "pending":
            retry.append(ip)
        else:
            done.setdefault(status, []).append(ip)
    with conn.transaction():
        for status, group in done.items():
            conn.execute("UPDATE ipinfo.submission SET processed_at = now(), last_status = %s "
                         "WHERE ip = ANY(%s::inet[]) AND processed_at IS NULL", (status, group))
        if retry:
            conn.execute("UPDATE ipinfo.submission SET attempts = attempts + 1, last_status = 'pending', "
                         "processed_at = CASE WHEN attempts + 1 >= %s THEN now() END "
                         "WHERE ip = ANY(%s::inet[]) AND processed_at IS NULL", (MAX_ATTEMPTS, retry))
    stats = Counter({f"submitted_{k}": len(v) for k, v in done.items()})
    if retry:
        stats["submitted_retry"] = len(retry)
    return dict(stats)

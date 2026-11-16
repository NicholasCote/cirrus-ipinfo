"""RPSL database dumps (RIPE NCC, APNIC, AFRINIC split dumps).

Objects are blocks of ``attribute: value`` lines separated by blank lines.
Continuation lines start with whitespace or ``+``, and ``#``/``%`` lines are
comments. Dumps are latin-1, so open them with ``encoding="latin-1"``.

Classes used:
* ``inetnum`` (``a.b.c.d - e.f.g.h``) and ``inet6num`` (CIDR): the networks
* ``organisation``: ``org-name``, plus an ``abuse-c`` fallback
* ``role``: ``nic-hdl`` -> ``abuse-mailbox``
* ``irt``: ``abuse-mailbox`` (APNIC uses ``mnt-irt`` on inetnums)

The public dumps are "dummified": personal data is removed. Any contact
that isn't present just stays None.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime

from .network import NetworkRecord

RpslObject = dict[str, list[str]]

_SOURCE_TO_RIR = {"RIPE": "ripencc", "APNIC": "apnic", "AFRINIC": "afrinic"}
_RIR_TO_DUMP = {"ripencc": "ripe_dump", "apnic": "apnic_dump", "afrinic": "afrinic_dump"}


def iter_objects(lines: Iterable[str]) -> Iterator[tuple[str, RpslObject]]:
    """Yield ``(class, attributes)`` for each object in an RPSL stream."""
    obj: RpslObject = {}
    cls: str | None = None
    last: str | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            if cls:
                yield cls, obj
            obj, cls, last = {}, None, None
            continue
        if line[0] in "#%":
            continue
        if line[0] in " \t+" and last is not None:
            cont = line[1:].strip()
            if cont:
                vals = obj[last]
                vals[-1] = f"{vals[-1]} {cont}".strip()
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.split("#", 1)[0].strip()  # strip end-of-line remarks
        if cls is None:
            cls = key
        obj.setdefault(key, []).append(value)
        last = key
    if cls:
        yield cls, obj


def _first(obj: RpslObject, key: str) -> str | None:
    vals = obj.get(key)
    return vals[0] if vals and vals[0] else None


def _ts(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_range(cls: str, value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if cls == "inetnum":
        a, _, b = value.partition("-")
        start, end = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
    else:
        net = ipaddress.ip_network(value.strip(), strict=False)
        start, end = net.network_address, net.broadcast_address
    return start, end


@dataclass
class RpslDatabase:
    """Accumulates objects from one or more dump files, then resolves references."""

    default_rir: str | None = None
    inetnums: list[tuple[str, RpslObject]] = field(default_factory=list)
    orgs: dict[str, RpslObject] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)   # nic-hdl -> abuse-mailbox
    irts: dict[str, str] = field(default_factory=dict)    # irt name -> abuse-mailbox

    def add(self, lines: Iterable[str]) -> None:
        for cls, obj in iter_objects(lines):
            if cls in ("inetnum", "inet6num"):
                self.inetnums.append((cls, obj))
            elif cls == "organisation":
                self.orgs[obj[cls][0].upper()] = obj
            elif cls == "role":
                h, mb = _first(obj, "nic-hdl"), _first(obj, "abuse-mailbox")
                if h and mb:
                    self.roles[h.upper()] = mb
            elif cls == "irt":
                mb = _first(obj, "abuse-mailbox")
                if mb:
                    self.irts[obj[cls][0].upper()] = mb

    def _abuse(self, obj: RpslObject, org: RpslObject | None) -> str | None:
        for ref in obj.get("abuse-c", []):
            if ref.upper() in self.roles:
                return self.roles[ref.upper()]
        for ref in obj.get("mnt-irt", []):
            if ref.upper() in self.irts:
                return self.irts[ref.upper()]
        if org:
            for ref in org.get("abuse-c", []):
                if ref.upper() in self.roles:
                    return self.roles[ref.upper()]
        return None

    def records(self) -> Iterator[NetworkRecord]:
        for cls, obj in self.inetnums:
            try:
                start, end = parse_range(cls, obj[cls][0])
            except ValueError:
                continue
            source_attr = (_first(obj, "source") or "").upper().split("-", 1)[0]
            rir = _SOURCE_TO_RIR.get(source_attr, self.default_rir)
            if rir is None:
                continue
            org_handle = _first(obj, "org")
            org = self.orgs.get(org_handle.upper()) if org_handle else None
            org_name = _first(org, "org-name") if org else None
            if org_name is None:
                # Many assignments have no org: object; descr is the
                # conventional holder description.
                org_name = _first(obj, "descr")
            yield NetworkRecord(
                start=start,
                end=end,
                rir=rir,
                source=_RIR_TO_DUMP[rir],
                handle=obj[cls][0],
                status=_first(obj, "status"),
                org_handle=org_handle,
                org=org_name,
                netname=_first(obj, "netname"),
                country=_first(obj, "country"),
                abuse_contact=self._abuse(obj, org),
                registered_at=_ts(_first(obj, "created")),
                rir_last_changed=_ts(_first(obj, "last-modified")),
            )

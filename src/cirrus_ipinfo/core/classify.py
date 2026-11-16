"""Classification layer: cloud provider ranges, Tor exits, blocklists.

Feed formats (checked against the live files on 2026-11-13):

* AWS ``ip-ranges.json``: ``prefixes[].{ip_prefix,region,service}``,
  ``ipv6_prefixes[].{ipv6_prefix,region,service}``. Every range appears with
  ``service: AMAZON`` *and* again with its specific service (EC2,
  CLOUDFRONT, ...), so the generic entry loses ties.
* GCP ``cloud.json``: ``prefixes[].{ipv4Prefix|ipv6Prefix,service,scope}``
* Oracle ``public_ip_ranges.json``: ``regions[].{region,cidrs[].{cidr,tags}}``
* Cloudflare ``ips-v4``/``ips-v6``: one CIDR per line
* Tor bulk exit list: one IP per line
* Spamhaus DROP ``drop_v4.json``/``drop_v6.json``: NDJSON ``{"cidr","sblid","rir"}``
  plus a trailing ``{"type":"metadata",...}`` line. EDROP has been merged into
  DROP; the old EDROP file now only says so.
* FireHOL ``*.netset``: one CIDR/IP per line, ``#`` comments. Note that
  ``firehol_level1`` includes bogons (RFC 1918 and so on), so special-purpose
  short-circuiting must happen first. The enricher does that.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .addr import IPAddress, IPNetwork
from .rangeindex import DualRangeIndex, parse_network


@dataclass(frozen=True)
class CloudTag:
    provider: str
    region: str | None = None
    service: str | None = None
    generic: bool = False


@dataclass(frozen=True)
class Classification:
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_service: str | None = None
    tor_exit: bool = False
    blocklists: tuple[str, ...] = ()


def _none(v: str | None) -> str | None:
    return v or None


def parse_aws(doc: dict) -> list[tuple[IPNetwork, CloudTag]]:
    out = []
    for key, pkey in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for p in doc.get(key, []):
            svc = p.get("service")
            out.append((parse_network(p[pkey]),
                        CloudTag("aws", _none(p.get("region")), _none(svc), generic=(svc == "AMAZON"))))
    return out


def parse_gcp(doc: dict) -> list[tuple[IPNetwork, CloudTag]]:
    out = []
    for p in doc.get("prefixes", []):
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        if cidr:
            out.append((parse_network(cidr), CloudTag("gcp", _none(p.get("scope")), _none(p.get("service")))))
    return out


def parse_oracle(doc: dict) -> list[tuple[IPNetwork, CloudTag]]:
    out = []
    for r in doc.get("regions", []):
        for c in r.get("cidrs", []):
            tags = c.get("tags") or []
            out.append((parse_network(c["cidr"]),
                        CloudTag("oracle", _none(r.get("region")), ",".join(tags) or None)))
    return out


def parse_netset(lines: Iterable[str]) -> list[IPNetwork]:
    """Plain lists: one CIDR or IP per line; ``#``/``;`` comments allowed."""
    out = []
    for line in lines:
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        try:
            out.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return out


def parse_spamhaus_drop(lines: Iterable[str]) -> list[IPNetwork]:
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if "cidr" in rec:
            out.append(parse_network(rec["cidr"]))
    return out


class Classifier:
    def __init__(
        self,
        cloud: list[tuple[IPNetwork, CloudTag]],
        tor_exits: list[IPNetwork],
        blocklists: dict[str, list[IPNetwork]],
    ):
        self._cloud: DualRangeIndex[CloudTag] = DualRangeIndex.from_networks(
            cloud, mode="most_specific", priority=lambda t: 1 if t.generic else 0
        )
        flags: list[tuple[IPNetwork, tuple[str, ...]]] = [(n, ("tor",)) for n in tor_exits]
        for name, nets in blocklists.items():
            flags.extend((n, ("blocklist", name)) for n in nets)
        self._flags: DualRangeIndex[tuple[str, ...]] = DualRangeIndex.from_networks(flags, mode="union")

    def classify(self, addr: IPAddress) -> Classification:
        tag: CloudTag | None = self._cloud.lookup(addr)
        flags = self._flags.lookup(addr)
        return Classification(
            cloud_provider=tag.provider if tag else None,
            cloud_region=tag.region if tag else None,
            cloud_service=tag.service if tag else None,
            tor_exit=("tor",) in flags,
            blocklists=tuple(sorted(f[1] for f in flags if f[0] == "blocklist")),
        )

"""GDEX metrics compatibility: the ``dssdb.ipinfo`` record, built from an enrichment record.

GDEX's loaders (NCAR/rda-python-metrics, ``PgIPInfo``) merge a local GeoLite2 City
lookup with an IPinfo Lite answer and cache the result in ``dssdb.ipinfo``. Every
usage loader then reads ``ip``, ``org_type``, ``country``, ``region`` and
``hostname`` (as ``unknown@<hostname>``) from that row. This module produces the
same row, field for field, so ``set_ipinfo`` can call this service instead:

    ip         canonical address
    hostname   PTR name, else ``<ip>.<as_domain>``, else the ip itself
    lat, lon   floats, 0 when unknown
    country    upper-case country name with dots for spaces (``UNITED.STATES``,
               ``P.R.CHINA``); ``UNKNOWN`` when it can't be named
    region     most specific subdivision, transliterated (``convert_chars``)
    city       transliterated city name, ``X`` when unknown
    postal, timezone
    org_name   IPinfo's AS name (else the description of the routing AS name, e.g.
               ``GOOGLE - Google LLC`` → ``Google LLC``, where IPinfo has no record)
    org_type   from the hostname's domain: NCAR (ucar.edu), UNIV, GOV, MIL, ORG,
               COM, NET, OTHER; ``-`` when there is no hostname
    stat_flag  ``A`` complete: stored by the nightly run, full registry data.
               ``M`` computed on demand: GDEX asks again on a later run, by when
               a submitted IP has been stored.
    ipinfo     the IPinfo Lite answer (``asn``, ``as_name``, ``as_domain``,
               ``country_code``, ``country``, ``continent_code``, ``continent``);
               GDEX stores it with ``json.dumps``
    bogon      true for special-purpose addresses (GDEX maps them to its shared
               ``0.0.0.0`` record)

Deliberate differences from the GDEX code, all in the direction of accuracy:
* Region/city/postal/time zone are only filled in when the city database agrees
  with IPinfo on the country (GDEX keeps GeoLite2's city even when IPinfo says
  another country).
* With several PTR names the forward-confirmed one wins (GDEX takes the lowest).
* IPv4-mapped IPv6 addresses come back as plain IPv4.
"""

from __future__ import annotations

import re
import unicodedata

from .category import Categorizer
from .model import EnrichmentRecord

_UCAR = re.compile(r"(@|\.)ucar\.edu$")
_TLD = re.compile(r"\.(mil|org|gov|edu|com|net)(\.\w\w|$)")
_PLAIN = re.compile(r"^[a-zA-Z0-9]+$")
_NOT_WORD = re.compile(r"[^a-zA-Z0-9_]")
# Letters NFKD does not decompose, transliterated the way unidecode does.
_EXTRA = str.maketrans({"ø": "o", "Ø": "O", "ß": "ss", "ł": "l", "Ł": "L", "đ": "d", "Đ": "D", "æ": "ae",
                        "Æ": "AE", "œ": "oe", "Œ": "OE", "ı": "i", "þ": "th", "Þ": "Th", "ð": "d", "Ð": "D",
                        "ħ": "h", "Ħ": "H", "ŀ": "l", "Ŀ": "L", "ŉ": "n", "ĸ": "q"})


def org_type(hostname: str | None) -> str:
    """rda_python_common ``get_org_type(None, hostname)``."""
    if not hostname:
        return "OTHER"
    if _UCAR.search(hostname):
        return "NCAR"
    m = _TLD.search(hostname)
    if m:
        t = m.group(1).upper()
        return "UNIV" if t == "EDU" else t
    return "OTHER"


def convert_chars(name: str | None, default: str | None = "X") -> str | None:
    """rda_python_common ``convert_chars``: ASCII letters, digits and underscores only."""
    if not name:
        return default
    if _PLAIN.match(name):
        return name
    ascii_ = unicodedata.normalize("NFKD", name.translate(_EXTRA)).encode("ascii", "ignore").decode().strip()
    return _NOT_WORD.sub("", ascii_) or default


def country_token(name: str | None) -> str:
    """``get_country_record_code``: ``United States`` → ``UNITED.STATES``; China → ``P.R.CHINA``."""
    token = name.replace(" ", ".").upper() if name else "UNKNOWN"
    return "P.R.CHINA" if token == "CHINA" else token


def _continent_name(code: str | None) -> str | None:
    return {"AF": "Africa", "AN": "Antarctica", "AS": "Asia", "EU": "Europe", "NA": "North America",
            "OC": "Oceania", "SA": "South America"}.get(code or "")


def ipinfo_lite(rec: EnrichmentRecord) -> dict | None:
    """The IPinfo Lite answer as its API returns it."""
    if rec.special_purpose:
        return {"ip": rec.ip, "bogon": True}
    if rec.ipinfo_asn is None and rec.ipinfo_as_name is None and rec.as_domain is None:
        return None     # IPinfo had no record (or wasn't loaded); GDEX stores no IPinfo answer either
    return {"ip": rec.ip, "asn": f"AS{rec.ipinfo_asn}" if rec.ipinfo_asn is not None else None,
            "as_name": rec.ipinfo_as_name, "as_domain": rec.as_domain, "country_code": rec.geo_country,
            "country": rec.geo_country_name, "continent_code": rec.geo_continent,
            "continent": _continent_name(rec.geo_continent)}


def hostname(rec: EnrichmentRecord) -> str:
    if rec.ptr:
        return rec.ptr
    if rec.as_domain:
        return f"{rec.ip}.{rec.as_domain}"
    return rec.ip


def record(rec: EnrichmentRecord, *, stored: bool) -> dict:
    """The ``dssdb.ipinfo`` row for ``rec``."""
    if rec.special_purpose:
        return {"ip": rec.ip, "hostname": rec.ip, "lat": 0.0, "lon": 0.0, "country": "UNKNOWN", "region": None,
                "city": "X", "postal": None, "timezone": None, "org_name": None, "org_type": "-",
                "stat_flag": "A", "bogon": True, "ipinfo": ipinfo_lite(rec)}
    host = hostname(rec)
    return {
        "ip": rec.ip,
        "hostname": host,
        "lat": float(rec.geo_lat) if rec.geo_lat else 0.0,
        "lon": float(rec.geo_lon) if rec.geo_lon else 0.0,
        "country": country_token(rec.geo_country_name),
        "region": convert_chars(rec.geo_subdivisions[-1]) if rec.geo_subdivisions else None,
        "city": convert_chars(rec.geo_city),
        "postal": rec.geo_postal,
        "timezone": rec.geo_timezone,
        "org_name": rec.ipinfo_as_name or Categorizer.as_description(rec.as_name),
        "org_type": "-" if host == rec.ip else org_type(host),
        "stat_flag": "A" if stored else "M",
        "bogon": False,
        "ipinfo": ipinfo_lite(rec),
    }

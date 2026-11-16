# Using CIRRUS IP info from GDEX metrics

GDEX metrics (NCAR/rda-python-metrics) looks IPs up in one place, `PgIPInfo.set_ipinfo()`:
it merges a local GeoLite2 City lookup with an IPinfo Lite answer and caches the result in
`dssdb.ipinfo`. The usage loaders then read `ip`, `org_type`, `country`, `region` and
`hostname` from that row. Every record this service returns carries a `gdex` block with
exactly that row, so `set_ipinfo()` can call the service instead of geoip2 + IPinfo + DNS.
`dssdb.ipinfo` stays the cache, and reports and joins are unchanged.

## The block

`GET /v1/ip/8.8.8.8?view=gdex`

```json
{
  "ip": "8.8.8.8",
  "hostname": "dns.google",
  "lat": 37.4223, "lon": -122.085,
  "country": "UNITED.STATES",
  "region": "California",
  "city": "MountainView",
  "postal": "94043",
  "timezone": "America/Los_Angeles",
  "org_name": "Google LLC",
  "org_type": "OTHER",
  "stat_flag": "A",
  "bogon": false,
  "ipinfo": {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
             "country_code": "US", "country": "United States", "continent_code": "NA",
             "continent": "North America"}
}
```

Each field follows the GDEX code:

| Field | Rule (as in `pg_ipinfo.py` / rda-python-common) |
|---|---|
| `hostname` | PTR name, else `<ip>.<as_domain>`, else the IP |
| `org_type` | `get_org_type(None, hostname)`: `NCAR` for `*.ucar.edu`, else `UNIV`/`GOV`/`MIL`/`ORG`/`COM`/`NET` from the domain, else `OTHER`; `-` when the hostname is the bare IP |
| `country` | IPinfo's country name, upper case with dots for spaces; `CHINA` → `P.R.CHINA`; `UNKNOWN` if none |
| `region`, `city` | `convert_chars()`: ASCII letters/digits/underscore only (`New York` → `NewYork`); region is the most specific subdivision; city `X` when unknown |
| `lat`, `lon` | 0 when unknown |
| `org_name` | IPinfo Lite's AS name |
| `ipinfo` | IPinfo Lite's answer, as the IPinfo Lite API returns it (store it with `json.dumps`) |
| `stat_flag` | `A`: stored by the nightly run, complete. `M`: computed on demand; ask again on a later run |
| `bogon` | special-purpose address (private, loopback, CGNAT, ...): use the shared `0.0.0.0` row as today. Not a `dssdb.ipinfo` column |

The full record (no `view=gdex`) also has registry ownership, routing, categories
(university, cloud, scanner, ...), cloud provider/region, Tor and blocklist flags, and
history. None of that is needed for the drop-in.

## Lookups, batches and submissions

* `GET /v1/ip/{ip}?view=gdex&submit=true&source=gdex`: one IP.
* `POST /v1/ip/batch?view=gdex` with `{"ips": [...], "submit": true, "source": "gdex"}`:
  up to 1000 IPs. The response is NDJSON with one line per input IP, in request order.
  Invalid input gives `{"ip": "...", "error": "not an IP address"}`.
* `POST /v1/submit` with `{"ips": [...], "source": "gdex"}`: queue up to 10,000 IPs without
  looking them up (e.g. a backfill of `dssdb.ipinfo`).

IPs the service hasn't stored are answered immediately from its local datasets and a live
reverse-DNS lookup, with `stat_flag: "M"`. With `submit: true` the nightly run (02:00 UTC)
then does a full enrichment (registry/RDAP included) and stores it. The next time GDEX asks
about an `M` row, it gets the stored record with `stat_flag: "A"`. That matches how
`set_ipinfo()` already treats `M` rows.

No authentication and no rate limit: the service is reachable from the UCAR network only
(casper included). Stored IPs come straight from the database. For new IPs the time is
reverse DNS, run 64 at a time with a 2 s timeout, so a batch of 1000 new IPs takes seconds
to about a minute depending on how many name servers are slow. Use a generous client timeout.

## Suggested change to `PgIPInfo`

Prefetch a log file's IPs in batches (this replaces `preset_ip_hostnames()`, since the
service does the reverse DNS), then build the row from the block in `set_ipinfo()`. Keep the
geoip2 + IPinfo path as a fallback for when the service can't be reached.

```python
import json
import requests

CIRRUS_URL = "https://ipinfo.k8s.ucar.edu"       # final name TBD; ipinfo-test.k8s.ucar.edu today
ROW_FIELDS = ("ip", "hostname", "lat", "lon", "country", "region", "city", "postal", "timezone",
              "org_name", "org_type", "stat_flag")

# in __init__: self.CIRRUS = {}

def cirrus_prefetch(self, ips):
    """Look a list of IPs up in batches of 1000; fills self.CIRRUS[ip] with gdex blocks."""
    ips = [ip for ip in {self.normalize_ip(ip) for ip in ips} if ip and ip not in self.CIRRUS]
    for i in range(0, len(ips), 1000):
        try:
            r = requests.post(f"{CIRRUS_URL}/v1/ip/batch", params={"view": "gdex"}, timeout=300,
                              json={"ips": ips[i:i + 1000], "submit": True, "source": "gdex"})
            r.raise_for_status()
        except requests.RequestException as e:
            self.pglog(f"cirrus ipinfo: {e}; using geoip2/ipinfo", self.LOGWRN)
            return
        for line in r.iter_lines():
            rec = json.loads(line)
            if "error" not in rec:
                self.CIRRUS[rec["ip"]] = rec

def cirrus_record(self, ip):
    """The dssdb.ipinfo row for ip from the service; BOGONIP for special-purpose; None if unavailable."""
    if ip not in self.CIRRUS:
        self.cirrus_prefetch([ip])
    rec = self.CIRRUS.get(ip)
    if rec is None:
        return None
    if rec["bogon"]:
        return self.BOGONIP
    row = {k: rec[k] for k in ROW_FIELDS}
    row["ipinfo"] = json.dumps(rec["ipinfo"]) if rec["ipinfo"] else None
    return row
```

In `set_ipinfo()`, where it now calls `get_ipinfo_answer()` and `get_geoip2_record()`:

```python
      if refresh or not pgrec or ipopt and pgrec['stat_flag'] == 'M':
         record = self.cirrus_record(ip)
         if record is self.BOGONIP:
            self.IPRECS[ip] = self.pgget('ipinfo', '*', f"ip = '{self.GIP}'", self.LGEREX)
            return self.IPRECS[ip]
         if record is None:                      # service down: the existing path
            iprec = self.get_ipinfo_answer(ip) if ipopt else None
            if iprec is self.BOGONIP: ...        # unchanged
            record = self.get_geoip2_record(ip, iprec)
         if record:
            self.update_ipinfo_record(record, pgrec)
            pgrec = record
```

`prescan_ips()` and the loaders' `preset_ip_hostnames(...)` calls can call
`cirrus_prefetch(...)` instead, so one log file costs a handful of requests.

## Differences from today's results

All of these come from choosing the more accurate value:

* Region, city, postal code and time zone are only filled in when the city database agrees
  with IPinfo on the country. Today a GeoLite2 city in one country can sit next to IPinfo's
  different country.
* When an address has several PTR names, the one that resolves back to the address wins.
  Today the alphabetically first name is used.
* IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) come back as plain IPv4.
* Location below country level comes from GeoLite2 City when it has the block, else from
  DB-IP City Lite (no postal code or time zone).

## Attribution

Data shown from this service carries: "IP address data powered by IPinfo" (CC BY-SA 4.0),
"This product includes GeoLite2 data created by MaxMind, available from
https://www.maxmind.com", and "IP Geolocation by DB-IP" (CC BY 4.0). The `attribution`
field of the full record lists them.

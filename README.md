# cirrus-ipinfo

CIRRUS's single source of truth for "what do we know about this IP": nightly, point-in-time
ownership, routing, geo, DNS and classification records for every client IP that reaches a
CIRRUS service.

**Status:** proof of concept. Design: [`docs/design/DESIGN.md`](docs/design/DESIGN.md).
Any IP can be looked up, including ones CIRRUS hasn't seen (computed on demand, optionally
submitted for the nightly run). GDEX metrics drop-in: [`docs/gdex-integration.md`](docs/gdex-integration.md).
The full README (data sources, licenses/attribution, retention, re-verification rules) is a
later deliverable.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Attribution

- IP address data powered by [IPinfo](https://ipinfo.io) (IPinfo Lite, CC BY-SA 4.0).
- [IP Geolocation by DB-IP](https://db-ip.com) (IP to City Lite, CC BY 4.0).
- This product includes GeoLite2 data created by MaxMind, available from
  [https://www.maxmind.com](https://www.maxmind.com) (GeoLite2 EULA).

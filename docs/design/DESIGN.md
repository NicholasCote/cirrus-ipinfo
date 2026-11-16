# cirrus-ipinfo — design proposal (for review)

Status: **revision 3.** Review decisions are folded in (§6). Implemented: core library, pipeline, API and lookup page, Helm chart (`deploy/helm/cirrus-ipinfo`).
Schema: the Alembic migrations in `src/cirrus_ipinfo/db/migrations/versions/` (0001 is the base DDL), tested on Postgres 18.

**What this is:** CIRRUS's single source of truth for "what do we know about this IP". Every authorised UCAR user can read all of it: the enrichment, the registry networks, and the observations (which IPs hit which tenant/host, and when). `tenant` is attribution, not an access boundary.

---

## 1. Repo layout

```
cirrus-ipinfo/
├── pyproject.toml, Dockerfile     # one image; entrypoint `cirrus-ipinfo` (api, nightly, migrate, ...)
├── src/cirrus_ipinfo/
│   ├── cli.py                     # command-line entry points
│   ├── sources.py                 # dataset URLs, licenses, download
│   ├── core/                      # shared by pipeline and API; no DB or k8s imports
│   │   ├── model.py, hashing.py   # enrichment record, layers, content hash
│   │   ├── enrich.py              # Enricher: ip → EnrichmentRecord
│   │   ├── localdb.py             # MMDB readers (IPinfo Lite, GeoLite2, DB-IP) + LocalData bundle
│   │   ├── routing.py, classify.py, special.py, dns.py, category.py, gdex.py, ...
│   │   └── registry/              # delegated stats, RDAP, RPSL dumps, transfers, resolver
│   ├── pipeline/                  # nightly stages: refresh, collect (Loki), enrich, load, submissions
│   ├── db/migrations/             # Alembic (SQL files per revision)
│   ├── api/                       # FastAPI app, on-demand engine, lookup page + static assets
│   └── data/                      # category rules, IANA special-purpose registries, public suffix list
├── tests/                         # unit + integration (Postgres 18 via IPINFO_TEST_DATABASE_URL)
├── deploy/helm/cirrus-ipinfo/     # Helm chart: CNPG, ExternalSecret, migrate hook, CronJobs, API
└── docs/                          # DESIGN.md, gdex-integration.md
```

---

## 2. Schema summary (full DDL in the migrations)

| Table | Notes |
|---|---|
| `dataset_snapshot` | One row per (source, snapshot_date). Adds `source_url`, `upstream_version`, `s3_uri`, `attribution`, `record_count`, and `pruned_at` (set when retention deletes the S3 object; the row is kept forever). |
| `pipeline_run` | Per-stage run records, including which `snapshot_ids` were used. Provides idempotency and audit. |
| `tenant` | Capsule tenant names, synced by `collect`. Reserved names: `_platform` and `_unmapped`. Attribution only. |
| `network` | **`range inetrange`** instead of `cidr` (registry ranges aren't CIDR-aligned). Also `span` for most-specific selection, `content_hash`, `last_verified_at`, `superseded_by`, and a generated `valid tstzrange` for as-of queries. Only ranges that cover observed IPs are stored. Full dumps stay on S3. |
| `ip_enrichment` | As specified, plus `valid_from date`, `registry_status`, `rir`, `origin_asns[]` (MOAS) and `ptr_status`. ASN is `bigint` (32-bit unsigned). Partial unique index on `(ip) WHERE superseded_at IS NULL` = the current version. Each version records `enricher_version` and `changed_layers` (§4.9). |
| `observation` | Monthly range partitions on `day` (UTC). Adds `namespace`, `hits_4xx/5xx`, `bytes`, plus denormalised `origin_asn/geo_country/cloud_provider/blocklisted` copied from the immutable enrichment version, so dashboards don't need a large join. |

**Indexes:**
- GiST on `network(range) WHERE current` and on `network(range, valid)`.
- GiST `inet_ops` on `ip_enrichment(ip)` for "IPs in prefix X".
- GIN on `blocklists`.
- On `observation`: `(tenant, day)`, `(tenant, origin_asn, day)`, `(ip)`, `(enrichment_id)`.

**Access (no RLS):**

| Role | Used by | Rights |
|---|---|---|
| `ipinfo_owner` | Alembic and partition DDL | Owns all objects |
| `ipinfo_writer` | Pipeline | DML on all tables |
| `ipinfo_api` | API | SELECT on all tables |
| `ipinfo_reader` | Everyone else | SELECT on all tables |

- People get `ipinfo_reader` through OpenBao **dynamic** credentials (`CREATE ROLE "{{name}}" … IN ROLE ipinfo_reader`).
- Grafana uses one OpenBao **static** role (rotated password) that is a member of `ipinfo_reader`, synced to the datasource by ESO.
- Default privileges grant the same rights on future partitions. This only works if the DDL runs as `ipinfo_owner` itself, so Alembic runs as (or `SET ROLE`s to) the owner, and partitions are created by the `SECURITY DEFINER` functions `ensure_observation_partitions()` / `drop_observation_partitions()`, which the writer may execute.
- Views: `observation_enriched` and `ip_enrichment_current`.

**Network exposure:** Postgres (via the CNPG Pooler) and the API each get a Cilium L2 LB Service address with an FQDN. These are reachable from the UCAR network only, with NetworkPolicy on top.

---

## 3. Pipeline job graph

```
continuous   Traefik (internal + external, mlc1 and nwc1) ─JSON─▶ Alloy ─▶ Loki   (unchanged, existing)

every 6h     sync-tenants   (CronJob in each cluster)
               namespaces + capsule.clastix.io/tenant → s3 tenants/cluster=C/namespaces.json

══════════════════════════════ mlc1 (home) ══════════════════════════════
02:00 UTC    nightly --date D   (one CronJob; every stage is also its own CLI command)
             ├─ maintain      ensure observation partitions (+2 months)
             ├─ refresh       fetch each source → s3 snapshots/D/ → dataset_snapshot
             │                a failed source falls back to its newest earlier snapshot (restored from S3)
             ├─ sync-tenants  (this cluster)
             ├─ collect       for C in mlc1, nwc1: Grafana datasource proxy → Loki query_range
             │                  {cluster=C, namespace="traefik"} | json … | line_format (fields only)
             │                  paginated per hour; attribution: KubernetesIngressNamespace, else
             │                  ServiceName/RouterName matched to real namespaces; tenant from the map
             │                → s3 collected/day=D/cluster=C/observations.jsonl.gz
             ├─ enrich        U = distinct IPs; current versions + network cache preloaded from the DB;
             │                local layers, registry (dump → cache → RDAP, budgeted), PTR + FCrDNS
             │                → s3 enrich/day=D/records.jsonl.gz
             ├─ load          one transaction: networks (raw RDAP → s3 rdap/), versions, fill-ins,
             │                observations (upsert, so re-runs are idempotent)
             └─ maintain      drop partitions past 13 months
             Every stage writes a pipeline_run row (stats, snapshot ids, error).
```

**Why Loki instead of a separate S3 log path:** the shared Alloy (v1.18.1, k8s-monitoring chart) can only write to S3 with `otelcol.exporter.awss3`, which is experimental and would need `--stability.level=experimental` on the platform log collector. Traefik logs are already in Loki, and Grafana can query it, so no Alloy change is needed. The trade-off: `collect` depends on Loki retention and query limits. A day can only be re-collected while Loki still has it.

**Why one `nightly` job and not chained CronJobs:** CronJobs can't depend on each other. A single job with explicit stages and `pipeline_run` checkpoints avoids adding Argo Workflows, and each stage can still be run on its own (`cirrus-ipinfo enrich --date D`).

**Re-run rules for date D:**
- `collect` is deterministic from the raw logs and overwrites its output.
- `refresh` won't replace a snapshot that an `enrich` has already consumed unless run with `--force`.
- `enrich`/`load` for the latest processed day behave as in the nightly run.
- For an older day (backfill, or a cluster's logs arriving late), `enrich` uses the snapshots dated D. Observations link to the version valid at D. A new version is inserted only if no version covers D. It is never inserted in front of a later version with different content.

---

## 4. Design rules that came out of review

**4.1 Collect attribution.** Fields read from Loki: ts, `ClientHost`, `RequestHost`, `ServiceName`, `RouterName`, `KubernetesIngressNamespace` (external Traefik only), status, bytes.
- The namespace comes from `RouterName`/`ServiceName`, because a host can route to several namespaces.
- Host matching is the fallback.
- `X-Forwarded-For` is never used.
- LoxiLB preserves the source IP on mlc1 now and on nwc1 after the pending update. Until then, nwc1 observations would record the LB address. `collect` sets `source_ip_suspect` in its stats when one IP carries over 80% of a cluster's requests, so this doesn't fail silently.
- Requests no router matched get namespace `_none` and tenant `_unmapped`. Namespaces without a tenant label (traefik, openbao, …) map to `_platform`.

**4.2 Registry fill-in (the single exception to "never rewrite history").** A `registry_status='pending'` row can be updated exactly once, within 7 days of `valid_from`:
- `network_id` goes from NULL to a value, and the status from `pending` to `resolved`.
- The category columns are completed with it, because they're derived from the registry (`org_name`, registry org keywords). No other column changes, `content_hash` is not recomputed, and the change is counted in `pipeline_run.stats` (`pending_filled_in`).
- After 7 days a still-pending IP gets a normal new version once it resolves.

**4.3 Other allowed mutations.** Bumping `last_verified_at` and setting `superseded_at`/`superseded_by` close an interval and are not treated as rewrites. Per-section verification timestamps come from:
- `network.last_verified_at` (registry)
- `ip_enrichment.last_verified_at` (local layers and PTR)
- `dataset_snapshot` (per-source dates)

**4.4 Point-in-time is per nightly snapshot.** Datasets are fetched around D+1 00:30 UTC and used for day D. RDAP and PTR are live, so they can't be reproduced for backfills. This will be documented.

**4.5 PTR churn.** Dynamic PTRs and geo-city values create new versions when they change. That's acceptable at this scale. If the version count grows too fast, PTR can move to its own table later.

**4.6 Retention.**
- Observations: 13 months, monthly partitions dropped by `maintain`.
- Raw reduced logs on S3: 14 days.
- Dataset snapshots: 35 daily snapshots plus the 1st of each month for 13 months. `maintain` deletes them (not an S3 lifecycle rule) so it can set `dataset_snapshot.pruned_at`.
- Raw RDAP responses (`rdap/`): **kept forever**, because old registry answers can't be fetched again.
- Enrichment and network versions: **kept in v1** (see §6, item 6). `maintain` reports table sizes and the count of unreferenced versions as metrics. Pruning can be added later as one step.

**4.7 API (v1).**
- `GET /v1/ip/{ip}` works for **any** IP:
  - It returns the stored current version if one exists (`stored: true`).
  - Otherwise it computes one on demand from the local datasets (kept in memory from the newest S3 snapshots, reloaded hourly when a newer one exists), the `network` table as a registry cache, and a live PTR lookup. It never calls RDAP and never writes an enrichment. Results are marked `stored: false` with `version: null`.
  - `?submit=true&source=<label>` queues the IP in `ipinfo.submission` if it isn't stored (or its version is over 90 days old). The nightly run enriches pending submissions together with the observed IPs and stores them as ordinary versions without observations. An IP left registry-`pending` (RDAP budget) is retried for up to 7 runs. `IPINFO_SUBMIT_MAX` (default 20,000) caps submissions per run.
- `POST /v1/ip/batch` takes `{"ips": [...], "submit": bool, "source": str}` (up to 1000) and returns `application/x-ndjson`, one line per input in request order. On-demand lookups run concurrently.
- `POST /v1/submit` queues up to 10,000 IPs without looking them up (202 with counts).
- Every record carries a `gdex` block: the `dssdb.ipinfo` row GDEX metrics stores today (`core/gdex.py`, see `docs/gdex-integration.md`). `view=gdex` returns only that block.
- `GET /v1/ip/{ip}/history` returns all stored versions (404 if none).
- `/healthz` (database) for liveness, `/readyz` (database + datasets loaded) for readiness.
- **No observations endpoint in v1.** Observations are queried through SQL and Grafana.
- No authentication. Access is limited by the UCAR-network-only address.
- Every section carries its source, snapshot date and verified-at, plus license attribution.

**4.8 Data-source notes to check during implementation.** None of these are confirmed yet. They'll be confirmed in `docs/data-sources.md` with current URLs and licenses before any code depends on them.
- I believe Spamhaus EDROP was merged into DROP, which also now has JSON and ASN-DROP variants.
- The Azure Service Tags download URL changes weekly.
- IPinfo Lite is CC-BY-SA, and the ShareAlike terms may extend to our derived tables if they're shared.
- DB-IP Lite requires attribution wherever its data is shown.
- FireHOL level1 includes bogons and RFC1918 ranges. The special-purpose check must run before blocklist matching, and a test will cover this.
- Origin ASN comes from the RIB. `as_name` is keyed by that ASN, not taken from IPinfo.
- I also need to check whether the deployed Alloy version can write logs to S3 (e.g. `otelcol.exporter.awss3`).

**4.9 Versioning: database vs. S3.** The database is the durable, versioned record. S3 holds the raw inputs and the daily outputs, at dated, write-once paths. That's why bucket versioning and object lock aren't used.
- Every `ip_enrichment` version has `changed_layers`, a subset of `registry`, `routing`, `geo`, `ptr`, `classification`, `initial` and `enricher`, computed against the previous version at load time. Ownership-change queries filter on `changed_layers && '{registry,routing}'`.
- `enricher_version` (package version plus a hash-schema version) separates code changes from data changes. If a new version differs from the previous one only because of our code, `changed_layers = '{enricher}'`.

**4.10 S3.**
- The endpoint is `https://s3.k8s.ucar.edu:5443` (RadosGW). Its certificate is publicly trusted (InCommon). Addressing is path-style, because bucket subdomains don't resolve.
- Credentials come from one OpenBao entry (`externalSecret.key` in the Helm values) via a SecretStore, rendered as standard `AWS_*` environment variables (`templates/externalsecret.yaml`).
- Prefixes in the bucket:

  | Prefix | Contents | Retention |
  |---|---|---|
  | `tenants/cluster=…/` | namespace → tenant map | overwritten |
  | `collected/day=…/cluster=…/` | `collect` output (gzip JSON lines) | 13 months |
  | `snapshots/<date>/<source>/` | raw datasets | `maintain` |
  | `derived/<date>/` | compiled range-index artefacts, pfx2as | `maintain` |
  | `enrich/day=…/` | daily enrichment output | 13 months |
  | `rdap/<rir>/<handle>/<fetched_at>.json` | raw RDAP responses | forever |

- Secrets come through a namespaced SecretStore `openbao` (Kubernetes auth, role `cirrus-ipinfo`), because the `openbao` ClusterSecretStore isn't present on mlc1.

**4.11 Categories (category → subcategory → organisation).** Research reporting needs broad buckets that can be drilled into, down to the institution (for example, did CU Boulder or Alabama access more?).

| Level | Column | Example | Source |
|---|---|---|---|
| 1 | `category` | `education_research` | rules (below) |
| 2 | `subcategory` | `university` | rules (below) |
| 3 | `org_domain` | `colorado.edu` | registered domain of the reverse DNS name, using the ICANN section of the Public Suffix List (so `cs.ox.ac.uk` → `ox.ac.uk`) |
| 3 | `org_name` | "Regents of the University of Colorado" | registry org, else AS name |

- Categories: `special`, `internal`, `anonymizer`, `cloud`, `education_research`, `government`, `commercial`, `nonprofit`, `unknown`.
- Rules live in `src/cirrus_ipinfo/data/category-rules.json`. They're curated, versioned, and their version is part of the hash, so a rule edit produces versions marked `enricher`, not silent changes.
- **Precedence (first match wins):**
  1. special
  2. internal (UCAR AS194, CIDRs, or a *confirmed* `ucar.edu` name)
  3. Tor
  4. cloud ranges
  5. domain overrides (e.g. `orcid.org`)
  6. ASN overrides (research networks)
  7. confirmed reverse-DNS suffix (`.edu`, `.ac.*`, `.gov`, `.mil`, `k12.*.us`, …)
  8. ASN type (PeeringDB)
  9. registry org keywords ("University", "Universidad", …)
  10. *unconfirmed* reverse-DNS suffix
  11. unknown
- A reverse DNS name that doesn't forward-confirm is weak evidence, because the reverse zone owner can claim any name. It never grants `internal`, and it's used only when nothing stronger matched. `category_basis` records which rule decided.
- AS14041 (FRGP) is UCAR-registered but is the regional research network serving other institutions, so it maps to `education_research/research_network`, not `internal`. A confirmed campus reverse DNS name takes precedence (`colostate.edu` → university).
- `legacy_category` reproduces the existing team report's buckets (reverse DNS TLD → COM/NET/UNIV/GOV/ORG/MIL, plus NCAR, orcid, `-` for no PTR, N/A for a failed lookup, OTHER) so the two can be compared side by side. It's an approximation until checked against their data.
- `observation` gets copies of `category`, `subcategory` and `org_domain`, with indexes for dashboard drill-downs.
- New sources: the Public Suffix List (MPL-2.0, vendored and refreshed nightly). PeeringDB ASN types are optional and **pending a license check**. Without them, `commercial` can't be split further and `cloud/other_hosting` stays empty.

---

## 5. Implementation details (not blocking)

- Local registry, routing and classification lookups use an in-memory **range index** (`core/rangeindex.py`): ranges are flattened once into sorted, non-overlapping segments, and a lookup is one bisect (about 2.5 µs per layer, measured on the real RIPE delegated and transfer files). This replaces the compiled `local.mmdb` idea: registry ranges aren't CIDRs and nest, and the index handles that directly with no MMDB writer. `compile` will serialise the built indexes to `derived/<date>/` so the API and `enrich` load the identical artefact.
- API pods sync the latest compiled snapshot from S3 (init container plus a periodic reload).
- The Grafana dashboard uses one datasource (the static reader role), with `cluster`, `tenant` and `host` variables. Panels: top ASNs/orgs, countries, cloud vs. other, blocklisted hits, and an IP drill-down table.

---

## 6. Decision log

| # | Question | Decision |
|---|---|---|
| 1 | Home cluster | mlc1 runs everything; nwc1 runs `collect` only |
| 2 | Alloy → S3 with RouterName/ServiceName | Yes |
| — | LoxiLB source IP | Preserved on mlc1; nwc1 update in a few days |
| — | DB/API reachability | Cilium L2 LB Service + FQDN, UCAR network only |
| 3 | Grafana tenancy | Not needed: one shared datasource |
| 4 | Visibility | **Everything readable by all**, observations included; no RLS |
| 5 | Pending registry data | One-time fill-in (§4.2) |
| 6 | Prune unreferenced versions | Undecided. Keep in v1 and track size, revisit with data |
| 7 | CronJob metrics | OTLP via Alloy |
| 8 | Tenant observations endpoint | Left out of v1 |
| 9 | Postgres | 18 (confirm CNPG image/operator version) |
| 10 | Categories | Three levels (category → subcategory → org domain/name), domain-based drill-down (§4.11) |
| 11 | Legacy buckets | Computed alongside for comparison (assumed yes, revisit after validation) |
| 12 | PeeringDB | Optional ASN-type source, pending license check |
| 13 | Log collection path | Query Loki through Grafana's datasource proxy (no Alloy change); one `collect` on mlc1 for both clusters, nwc1 only publishes its tenant map |
| 14 | Pending fill-in vs. categories | Fill-in also completes the derived category columns |
| 15 | Secrets | Namespaced SecretStore with OpenBao Kubernetes auth (the `openbao` ClusterSecretStore isn't on mlc1) |
| 16 | In-cluster traffic | `collect` drops each cluster's pod/service CIDRs (`excludeCidrs` in values; counted as `excluded_in_cluster`). Other private space is kept (e.g. partner 10.116/16 over VPN) |
| 17 | API v1 scope | Stored data only (lookup, history, batch, summary) + a small lookup page and `/docs`; on-demand enrichment of never-seen IPs later |
| 18 | PeeringDB | AUP restricts storing/bulk download without approval; "Internet research and analysis" qualifies as a purpose. Ask support@peeringdb.com for written approval before ingesting |
| 19 | Categories v2 (rules version 2) | New top-level `automated` (scanners, search engines, SEO/AI crawlers); `cloud` covers hosting; curated ASNs (checked against RIPE asn.txt); org/AS-name keyword regexes; PTR line-type tokens; legal-form fallback → `commercial/company`; RIPE maintainer handles ignored as org names. Unknown on the first mlc1 day fell from 283 to 2 IPs |
| 20 | Re-running a day | Replaces that day's own versions in place (`same_day_replaced`), so a rules change can be applied to the latest day; other days' versions are never rewritten |
| 21 | ingress-nginx | Collected alongside Traefik as a second log source (`logSources` in values; formats `traefik`, `nginx` default text, or `json` with a field map). `observation.ingress` (migration 0003, in the PK) records the controller, so namespaces still on nginx can be found. The default nginx format has no hostname, so its "application" is the upstream `<ns>-<svc>-<port>`. Not yet run against real nginx logs |
| 22 | Cluster nodes | `internal/k8s_node` (confirmed `mlc1*/nwc1*.k8s.ucar.edu` names, or listed node CIDRs; rules version 3) is dropped before load by default (`dropCategories`); counts kept in load stats |
| 23 | Unstored IPs (GDEX) | Computed on demand (`stored: false`, no RDAP, no writes) and optionally submitted for the nightly run (`ipinfo.submission`, migration 0004). Requested by GDEX metrics, whose IPs (Globus, THREDDS, OSDF, AWS, Zenodo) mostly never reach a CIRRUS ingress |
| 24 | GeoLite2 City | Added (needs a MaxMind account ID + license key in OpenBao). Country still comes from IPinfo Lite; region/subdivisions/city/postal/time zone/coordinates come from GeoLite2, else DB-IP, only if that database agrees on the country. Hash schema 3 (all IPs get one `enricher` version) |
| 25 | IPinfo AS label | IPinfo Lite's ASN, AS name and `as_domain` are stored as their own `asinfo` layer, so a relabel never shows up as a routing change. Routing's origin ASN/AS name still come from RouteViews/RIPE |
| 26 | GDEX compatibility | `gdex` block reproduces `PgIPInfo.get_geoip2_record` + `merge_ipinfo_answer` + `get_org_type` + `convert_chars`. `stat_flag` is `A` for stored records and `M` for on-demand ones, so GDEX's loaders ask again (and get the stored record) on a later run |

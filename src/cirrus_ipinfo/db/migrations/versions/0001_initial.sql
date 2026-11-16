-- Revision 0001: initial schema. Generated from docs/design/schema.sql;
-- after this revision exists, schema changes go in new revisions, not here.
--
-- Runs as ipinfo_owner (env.py does SET ROLE), so every object is owned by
-- it and the default privileges at the end apply to later partitions.
-- Roles are created by CNPG managed roles, not here.

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['ipinfo_owner','ipinfo_writer','ipinfo_api','ipinfo_reader'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      RAISE EXCEPTION 'role % missing: it is created by the CNPG Cluster managed roles', r;
    END IF;
  END LOOP;
END $$;

CREATE SCHEMA IF NOT EXISTS ipinfo AUTHORIZATION ipinfo_owner;
SET LOCAL search_path = ipinfo, pg_catalog;

------------------------------------------------------------------------------
-- Types
------------------------------------------------------------------------------
-- Registry objects (inetnum, RDAP startAddress/endAddress) are arbitrary ranges,
-- not CIDRs, so `network.range` cannot be `cidr`. A range type over inet gives
-- GiST-indexable containment (range @> ip) with no extension (ip4r is not in
-- the stock CNPG images).
CREATE TYPE inetrange AS RANGE (subtype = inet);

------------------------------------------------------------------------------
-- Provenance
------------------------------------------------------------------------------
CREATE TABLE dataset_snapshot (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source         text        NOT NULL,      -- e.g. ipinfo_lite, dbip_city_lite, routeviews_rib,
                                            -- ripe_db, apnic_db, afrinic_db, delegated_<rir>,
                                            -- transfers_<rir>, aws, gcp, azure, oci, cloudflare,
                                            -- tor_exits, spamhaus_drop, firehol_level1, asnames,
                                            -- iana_special, iana_rdap_bootstrap, compiled_local
  snapshot_date  date        NOT NULL,      -- data day this snapshot serves
  fetched_at     timestamptz NOT NULL,
  source_url     text        NOT NULL,
  upstream_version text,                    -- serial / Last-Modified / ETag / file date
  s3_uri         text        NOT NULL,
  checksum       text        NOT NULL,      -- sha256 of the raw artefact
  size_bytes     bigint      NOT NULL,
  record_count   bigint,
  license        text        NOT NULL,      -- SPDX id or short name, e.g. CC-BY-4.0
  attribution    text,                      -- exact attribution string to surface in API/Grafana
  pruned_at      timestamptz,               -- set by `maintain` when the S3 object is deleted by
                                            -- retention; the row (provenance) is kept forever
  UNIQUE (source, snapshot_date)
);
CREATE INDEX dataset_snapshot_latest ON dataset_snapshot (source, snapshot_date DESC);

CREATE TABLE pipeline_run (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_date     date        NOT NULL,        -- data day (UTC)
  stage        text        NOT NULL CHECK (stage IN ('refresh','collect','sync_tenants','enrich','load','maintain')),
  cluster      text        CHECK (cluster IN ('mlc1','nwc1')),   -- collect only
  started_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz,
  status       text        NOT NULL DEFAULT 'running' CHECK (status IN ('running','succeeded','failed')),
  snapshot_ids bigint[]    NOT NULL DEFAULT '{}',  -- dataset_snapshot ids the stage used
  stats        jsonb       NOT NULL DEFAULT '{}',
  error        text
);
CREATE INDEX pipeline_run_lookup ON pipeline_run (run_date, stage, cluster, started_at DESC);

------------------------------------------------------------------------------
-- Tenants (synced from Capsule Tenant objects reported by each cluster's collect)
------------------------------------------------------------------------------
CREATE TABLE tenant (
  name        text PRIMARY KEY,               -- Capsule tenant name; '_platform', '_unmapped' reserved
  created_at  timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz
);

------------------------------------------------------------------------------
-- Registry networks (point-in-time; new row only when content changes)
------------------------------------------------------------------------------
-- Only ranges that cover at least one observed IP are materialised here. Full
-- dumps live in S3 (parquet) and in the compiled local MMDB.
CREATE TABLE network (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  range            inetrange NOT NULL,
  cidrs            cidr[]    NOT NULL,        -- CIDR decomposition of range (display/export)
  span             numeric(39,0) NOT NULL CHECK (span > 0),  -- address count; smallest = most specific
  rir              text NOT NULL CHECK (rir IN ('arin','ripencc','apnic','lacnic','afrinic')),
  source           text NOT NULL CHECK (source IN ('rdap','ripe_dump','apnic_dump','afrinic_dump','delegated_stats')),
  handle           text,                      -- RDAP handle / inetnum key
  parent_handle    text,
  status           text,                      -- e.g. ASSIGNED PA, allocated, reassignment
  org_handle       text,
  org              text,
  netname          text,
  country          text CHECK (country ~ '^[A-Z]{2}$'),
  abuse_contact    text,
  registered_at    timestamptz,
  rir_last_changed timestamptz,
  raw_s3_uri       text,                      -- raw RDAP JSON / RPSL object for audit; the rdap/
                                              -- prefix is excluded from S3 lifecycle (kept forever)
  snapshot_id      bigint REFERENCES dataset_snapshot (id),  -- set for dump/delegated sources
  content_hash     bytea NOT NULL,
  fetched_at       timestamptz NOT NULL,      -- first fetch that produced this content
  last_verified_at timestamptz NOT NULL,      -- latest fetch that confirmed it
  superseded_at    timestamptz,               -- closed when content changes or range disappears
  superseded_by    bigint REFERENCES network (id),
  valid            tstzrange GENERATED ALWAYS AS (tstzrange(fetched_at, superseded_at, '[)')) STORED,
  CHECK (NOT isempty(range) AND lower_inc(range) AND upper_inc(range)),
  CHECK (family(lower(range)) = family(upper(range))),
  CHECK (masklen(lower(range)) = CASE family(lower(range)) WHEN 4 THEN 32 ELSE 128 END),
  CHECK (masklen(upper(range)) = CASE family(upper(range)) WHEN 4 THEN 32 ELSE 128 END),
  CHECK (last_verified_at >= fetched_at),
  CHECK (superseded_at IS NULL OR superseded_at >= fetched_at)
);
-- Current most-specific lookup:  WHERE range @> $ip AND superseded_at IS NULL ORDER BY span LIMIT 1
CREATE INDEX network_range_current ON network USING gist (range) WHERE superseded_at IS NULL;
-- As-of lookup:  WHERE range @> $ip AND valid @> $ts
CREATE INDEX network_range_valid   ON network USING gist (range, valid);
CREATE UNIQUE INDEX network_current_uq ON network (source, range) WHERE superseded_at IS NULL;
CREATE INDEX network_refetch_due   ON network (rir, last_verified_at) WHERE superseded_at IS NULL AND source = 'rdap';
CREATE INDEX network_org           ON network (org_handle);

------------------------------------------------------------------------------
-- Per-IP enrichment versions (append-only except: last_verified_at bump,
-- superseded_at close, and the one-time registry fill-in — see DESIGN.md §4.2)
------------------------------------------------------------------------------
CREATE TABLE ip_enrichment (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip                inet NOT NULL CHECK (masklen(ip) = CASE family(ip) WHEN 4 THEN 32 ELSE 128 END),
  valid_from        date NOT NULL,            -- first data day this version applies to
  -- registry layer
  network_id        bigint REFERENCES network (id),
  registry_status   text NOT NULL CHECK (registry_status IN ('resolved','pending','not_applicable','failed')),
  rir               text CHECK (rir IN ('arin','ripencc','apnic','lacnic','afrinic')),  -- from delegated stats
  -- routing layer
  origin_asn        bigint CHECK (origin_asn BETWEEN 0 AND 4294967295),  -- 32-bit unsigned
  origin_asns       bigint[],                 -- all origins when MOAS
  as_name           text,
  announced_prefix  cidr,
  -- geo layer
  geo_country       text CHECK (geo_country ~ '^[A-Z]{2}$'),
  geo_region        text,
  geo_city          text,
  -- DNS layer
  ptr               text,
  fcrdns            boolean,
  ptr_status        text CHECK (ptr_status IN ('ok','nxdomain','servfail','timeout','skipped')),
  -- classification layer
  cloud_provider    text,
  cloud_region      text,
  cloud_service     text,
  tor_exit          boolean NOT NULL DEFAULT false,
  blocklists        text[]  NOT NULL DEFAULT '{}',
  special_purpose   text,                     -- IANA special-purpose registry name; non-null => no lookups
  -- category layer (core/category.py + data/category-rules.json)
  category          text NOT NULL,            -- e.g. education_research, cloud, government, commercial
  subcategory       text,                     -- e.g. university, aws, us_military, isp_broadband
  org_domain        text,                     -- registrable domain of the PTR (ICANN PSL): colorado.edu
  org_name          text,                     -- registry org, else AS name
  category_basis    text NOT NULL,            -- evidence that decided: ptr_suffix, cloud_range, asn_type, ...
  legacy_category   text,                     -- existing team report buckets (COM/NET/UNIV/...), for comparison
  -- versioning
  content_hash      bytea NOT NULL,
  first_verified_at timestamptz NOT NULL,
  last_verified_at  timestamptz NOT NULL,
  superseded_at     timestamptz,
  snapshot_ids      bigint[] NOT NULL,        -- snapshots that produced this version
  enricher_version  text NOT NULL,            -- package version + hash-schema version, e.g. '0.1.0+h1'
  changed_layers    text[] NOT NULL,          -- vs. the previous version; '{initial}' for the first.
                                              -- '{enricher}' alone = only our code changed, not the data
  UNIQUE (ip, valid_from),
  CHECK (last_verified_at >= first_verified_at),
  CHECK (special_purpose IS NULL OR registry_status = 'not_applicable'),
  CHECK (cardinality(changed_layers) > 0 AND changed_layers <@
         ARRAY['initial','registry','routing','geo','ptr','classification','category','enricher']::text[])
);
CREATE UNIQUE INDEX ip_enrichment_current_uq ON ip_enrichment (ip) WHERE superseded_at IS NULL;
CREATE INDEX ip_enrichment_ip_gist   ON ip_enrichment USING gist (ip inet_ops);   -- "IPs inside prefix X"
CREATE INDEX ip_enrichment_network   ON ip_enrichment (network_id);
CREATE INDEX ip_enrichment_asn       ON ip_enrichment (origin_asn);
CREATE INDEX ip_enrichment_pending   ON ip_enrichment (valid_from) WHERE registry_status = 'pending';
CREATE INDEX ip_enrichment_blocklist ON ip_enrichment USING gin (blocklists);
-- "Which IPs changed ownership/routing since X":
--   WHERE valid_from >= X AND changed_layers && '{registry,routing}'
CREATE INDEX ip_enrichment_changes   ON ip_enrichment USING gin (changed_layers);
CREATE INDEX ip_enrichment_category  ON ip_enrichment (category, subcategory) WHERE superseded_at IS NULL;
CREATE INDEX ip_enrichment_org       ON ip_enrichment (org_domain) WHERE superseded_at IS NULL;

------------------------------------------------------------------------------
-- Observations (monthly partitions, 13-month retention)
------------------------------------------------------------------------------
CREATE TABLE observation (
  day             date   NOT NULL,            -- UTC
  cluster         text   NOT NULL CHECK (cluster IN ('mlc1','nwc1')),
  tenant          text   NOT NULL REFERENCES tenant (name),
  namespace       text   NOT NULL,
  host            text   NOT NULL,
  ip              inet   NOT NULL,
  hits            bigint NOT NULL CHECK (hits > 0),
  hits_4xx        bigint NOT NULL DEFAULT 0,
  hits_5xx        bigint NOT NULL DEFAULT 0,
  bytes           bigint NOT NULL DEFAULT 0,
  first_seen      timestamptz NOT NULL,
  last_seen       timestamptz NOT NULL,
  enrichment_id   bigint NOT NULL REFERENCES ip_enrichment (id),
  -- Denormalised from the (immutable) enrichment version, for dashboard filters
  origin_asn      bigint,
  geo_country     text,
  cloud_provider  text,
  blocklisted     boolean NOT NULL DEFAULT false,
  category        text,
  subcategory     text,
  org_domain      text,
  PRIMARY KEY (day, cluster, tenant, namespace, host, ip),
  CHECK (last_seen >= first_seen)
) PARTITION BY RANGE (day);

CREATE INDEX observation_tenant_day ON observation (tenant, day);
CREATE INDEX observation_tenant_asn ON observation (tenant, origin_asn, day);
CREATE INDEX observation_category   ON observation (category, subcategory, day);
CREATE INDEX observation_org        ON observation (org_domain, day);
CREATE INDEX observation_ip         ON observation (ip);
CREATE INDEX observation_enrichment ON observation (enrichment_id);


------------------------------------------------------------------------------
-- Views (security_invoker: privileges are checked as the querying role)
------------------------------------------------------------------------------
CREATE VIEW ip_enrichment_current WITH (security_invoker = true) AS
  SELECT * FROM ip_enrichment WHERE superseded_at IS NULL;

CREATE VIEW observation_enriched WITH (security_invoker = true) AS
  SELECT o.day, o.cluster, o.tenant, o.namespace, o.host, o.ip,
         o.hits, o.hits_4xx, o.hits_5xx, o.bytes, o.first_seen, o.last_seen,
         e.id AS enrichment_id, e.origin_asn, e.as_name, e.announced_prefix,
         e.geo_country, e.geo_region, e.geo_city, e.ptr, e.fcrdns,
         e.cloud_provider, e.cloud_region, e.cloud_service, e.tor_exit, e.blocklists,
         e.special_purpose, e.registry_status,
         e.category, e.subcategory, e.org_domain, e.org_name, e.category_basis, e.legacy_category,
         n.org, n.netname, n.country AS registry_country, n.rir, n.abuse_contact,
         n.range AS registry_range
  FROM observation o
  JOIN ip_enrichment e ON e.id = o.enrichment_id
  LEFT JOIN network n  ON n.id = e.network_id;

------------------------------------------------------------------------------
-- Ownership & grants
------------------------------------------------------------------------------
ALTER TABLE dataset_snapshot OWNER TO ipinfo_owner;
ALTER TABLE pipeline_run     OWNER TO ipinfo_owner;
ALTER TABLE tenant           OWNER TO ipinfo_owner;
ALTER TABLE network          OWNER TO ipinfo_owner;
ALTER TABLE ip_enrichment    OWNER TO ipinfo_owner;
ALTER TABLE observation      OWNER TO ipinfo_owner;
ALTER VIEW  ip_enrichment_current OWNER TO ipinfo_owner;
ALTER VIEW  observation_enriched  OWNER TO ipinfo_owner;
ALTER TYPE  inetrange        OWNER TO ipinfo_owner;

GRANT USAGE ON SCHEMA ipinfo TO ipinfo_writer, ipinfo_api, ipinfo_reader;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ipinfo TO ipinfo_writer;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ipinfo TO ipinfo_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA ipinfo TO ipinfo_api, ipinfo_reader;

-- Partitions created later by `maintain` inherit these grants ONLY if the DDL
-- runs as ipinfo_owner itself (login role must `SET ROLE ipinfo_owner` first;
-- otherwise the login role owns the partition and the defaults do not apply).
-- Readers may query partitions directly; there is no RLS to bypass.
ALTER DEFAULT PRIVILEGES FOR ROLE ipinfo_owner IN SCHEMA ipinfo
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ipinfo_writer;
ALTER DEFAULT PRIVILEGES FOR ROLE ipinfo_owner IN SCHEMA ipinfo
  GRANT SELECT ON TABLES TO ipinfo_api, ipinfo_reader;

------------------------------------------------------------------------------
-- Partition management (called by `maintain`; SECURITY DEFINER so the writer
-- doesn't need owner rights, and partitions are owned by ipinfo_owner, which
-- makes the default privileges above apply to them)
------------------------------------------------------------------------------
CREATE FUNCTION ensure_observation_partitions(months_ahead int DEFAULT 2)
RETURNS SETOF text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ipinfo, pg_catalog AS $$
DECLARE
  m date := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
  name text;
BEGIN
  FOR i IN 0..months_ahead LOOP
    name := format('observation_%s', to_char(m, 'YYYY_MM'));
    IF to_regclass(name) IS NULL THEN
      EXECUTE format('CREATE TABLE %I PARTITION OF observation FOR VALUES FROM (%L) TO (%L)',
                     name, m, (m + interval '1 month')::date);
      RETURN NEXT name;
    END IF;
    m := (m + interval '1 month')::date;
  END LOOP;
END $$;

CREATE FUNCTION drop_observation_partitions(retention_months int DEFAULT 13)
RETURNS SETOF text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ipinfo, pg_catalog AS $$
DECLARE
  cutoff date := (date_trunc('month', now() AT TIME ZONE 'UTC') - make_interval(months => retention_months))::date;
  part record;
BEGIN
  FOR part IN
    SELECT c.relname FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname = 'observation' AND p.relnamespace = 'ipinfo'::regnamespace
      AND c.relname ~ '^observation_[0-9]{4}_[0-9]{2}$'
      AND to_date(substr(c.relname, 13), 'YYYY_MM') < cutoff
  LOOP
    EXECUTE format('DROP TABLE %I', part.relname);
    RETURN NEXT part.relname;
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION ensure_observation_partitions(int), drop_observation_partitions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ensure_observation_partitions(int), drop_observation_partitions(int) TO ipinfo_writer;

SELECT ensure_observation_partitions(2);

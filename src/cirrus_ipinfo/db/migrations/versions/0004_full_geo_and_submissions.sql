-- Revision 0004
-- * ip_enrichment: the rest of the geo layer (GeoLite2 City / DB-IP: country name, continent,
--   every subdivision level, postal code, time zone, coordinates, accuracy) and IPinfo Lite's
--   AS label (its ASN, operator name and domain) as a separate 'asinfo' layer.
-- * submission: IPs other services (e.g. GDEX metrics) hand in for full enrichment. The nightly
--   run enriches pending submissions with the day's observed IPs and stores them as versions.
SET LOCAL search_path = ipinfo, pg_catalog;

ALTER TABLE ip_enrichment
  ADD COLUMN geo_country_name text,
  ADD COLUMN geo_continent    text CHECK (geo_continent ~ '^[A-Z]{2}$'),
  ADD COLUMN geo_subdivisions text[] NOT NULL DEFAULT '{}',
  ADD COLUMN geo_postal       text,
  ADD COLUMN geo_timezone     text,
  ADD COLUMN geo_lat          double precision CHECK (geo_lat BETWEEN -90 AND 90),
  ADD COLUMN geo_lon          double precision CHECK (geo_lon BETWEEN -180 AND 180),
  ADD COLUMN geo_accuracy_km  integer,
  ADD COLUMN geo_source       text,             -- geolite2_city | dbip_city_lite (below country level)
  ADD COLUMN ipinfo_asn       bigint CHECK (ipinfo_asn BETWEEN 0 AND 4294967295),
  ADD COLUMN ipinfo_as_name   text,
  ADD COLUMN as_domain        text;

ALTER TABLE ip_enrichment DROP CONSTRAINT ip_enrichment_changed_layers_check;
ALTER TABLE ip_enrichment ADD CONSTRAINT ip_enrichment_changed_layers_check
  CHECK (cardinality(changed_layers) > 0 AND changed_layers <@
         ARRAY['initial','registry','routing','geo','asinfo','ptr','classification','category','enricher']::text[]);

CREATE TABLE submission (
  ip                 inet PRIMARY KEY CHECK (masklen(ip) = CASE family(ip) WHEN 4 THEN 32 ELSE 128 END),
  sources            text[] NOT NULL DEFAULT '{}',   -- who asked (free-form label, e.g. 'gdex')
  first_submitted_at timestamptz NOT NULL DEFAULT now(),
  last_submitted_at  timestamptz NOT NULL DEFAULT now(),
  submit_count       integer NOT NULL DEFAULT 1,
  attempts           integer NOT NULL DEFAULT 0,      -- nightly runs that left it registry-pending
  processed_at       timestamptz,                     -- NULL = waiting for the nightly run
  last_status        text                             -- registry_status (or 'dropped'/'special') when processed
);
CREATE INDEX submission_pending ON submission (first_submitted_at) WHERE processed_at IS NULL;

-- The API queues submissions; the nightly (writer) processes them.
GRANT SELECT, INSERT, UPDATE ON submission TO ipinfo_api;

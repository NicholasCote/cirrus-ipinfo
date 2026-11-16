-- Revision 0003: which ingress controller served each observation (traefik, ingress-nginx, ...),
-- so traffic still on ingress-nginx can be found during the move to Traefik.
SET LOCAL search_path = ipinfo, pg_catalog;

ALTER TABLE observation ADD COLUMN ingress text NOT NULL DEFAULT 'traefik';
ALTER TABLE observation DROP CONSTRAINT observation_pkey;
ALTER TABLE observation ADD PRIMARY KEY (day, cluster, ingress, tenant, namespace, host, ip);
CREATE INDEX observation_ingress ON observation (ingress, namespace, day);

-- same view as 0001, plus o.ingress at the end (CREATE OR REPLACE may only append columns)
CREATE OR REPLACE VIEW observation_enriched WITH (security_invoker = true) AS
  SELECT o.day, o.cluster, o.tenant, o.namespace, o.host, o.ip,
         o.hits, o.hits_4xx, o.hits_5xx, o.bytes, o.first_seen, o.last_seen,
         e.id AS enrichment_id, e.origin_asn, e.as_name, e.announced_prefix,
         e.geo_country, e.geo_region, e.geo_city, e.ptr, e.fcrdns,
         e.cloud_provider, e.cloud_region, e.cloud_service, e.tor_exit, e.blocklists,
         e.special_purpose, e.registry_status,
         e.category, e.subcategory, e.org_domain, e.org_name, e.category_basis, e.legacy_category,
         n.org, n.netname, n.country AS registry_country, n.rir, n.abuse_contact,
         n.range AS registry_range,
         o.ingress
  FROM observation o
  JOIN ip_enrichment e ON e.id = o.enrichment_id
  LEFT JOIN network n  ON n.id = e.network_id;

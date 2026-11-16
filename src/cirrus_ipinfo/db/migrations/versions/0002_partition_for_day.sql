-- Revision 0002: create the observation partition for any given day (backfills).
-- SECURITY DEFINER like ensure_observation_partitions(), so the writer can call it
-- and the partition is owned by ipinfo_owner (default privileges apply).
SET LOCAL search_path = ipinfo, pg_catalog;

CREATE FUNCTION ensure_observation_partition_for(d date)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ipinfo, pg_catalog AS $$
DECLARE
  m date := date_trunc('month', d)::date;
  name text := format('observation_%s', to_char(m, 'YYYY_MM'));
BEGIN
  IF to_regclass(name) IS NULL THEN
    EXECUTE format('CREATE TABLE %I PARTITION OF observation FOR VALUES FROM (%L) TO (%L)',
                   name, m, (m + interval '1 month')::date);
    RETURN name;
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION ensure_observation_partition_for(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ensure_observation_partition_for(date) TO ipinfo_writer;

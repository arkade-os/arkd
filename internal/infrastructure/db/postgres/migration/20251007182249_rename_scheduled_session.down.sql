BEGIN;

CREATE TABLE IF NOT EXISTS market_hour (
   id SERIAL PRIMARY KEY,
   start_time BIGINT NOT NULL,
   end_time BIGINT NOT NULL,
   period BIGINT NOT NULL,
   round_interval BIGINT NOT NULL,
   updated_at BIGINT NOT NULL
);

DO $$
DECLARE
  seq_name text;
  max_id bigint;
  src_exists boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name = 'scheduled_session'
  ) INTO src_exists;

  IF src_exists THEN
    EXECUTE 'LOCK TABLE scheduled_session IN ACCESS EXCLUSIVE MODE';

    INSERT INTO market_hour (id, start_time, end_time, period, round_interval, updated_at)
    SELECT id, start_time, end_time, period, duration, updated_at
    FROM scheduled_session
    ORDER BY id ASC;

    EXECUTE 'DROP TABLE scheduled_session';
  END IF;

  SELECT pg_get_serial_sequence('market_hour', 'id') INTO seq_name;
  SELECT MAX(id) FROM market_hour INTO max_id;

  IF seq_name IS NOT NULL THEN
    IF max_id IS NULL THEN
      PERFORM setval(seq_name, 1, false);
    ELSE
      PERFORM setval(seq_name, max_id, true);
    END IF;
  END IF;
END
$$;

COMMIT;
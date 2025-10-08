BEGIN;

CREATE TABLE IF NOT EXISTS scheduled_session (
   id SERIAL PRIMARY KEY,
   start_time BIGINT NOT NULL,
   end_time BIGINT NOT NULL,
   period BIGINT NOT NULL,
   duration BIGINT NOT NULL,
   updated_at BIGINT NOT NULL
);

DO $$
DECLARE
  seq_name text;
  max_id bigint;
  src_exists boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name = 'market_hour'
  ) INTO src_exists;

  IF src_exists THEN
    -- Prevent concurrent writes during the copy
    EXECUTE 'LOCK TABLE market_hour IN ACCESS EXCLUSIVE MODE';

    INSERT INTO scheduled_session (id, start_time, end_time, period, duration, updated_at)
    SELECT id, start_time, end_time, period, round_interval, updated_at
    FROM market_hour
    ORDER BY id ASC;

    -- Drop the old table after copy
    EXECUTE 'DROP TABLE market_hour';
  END IF;

  -- Fix the SERIAL sequence regardless of whether we copied any rows
  SELECT pg_get_serial_sequence('scheduled_session', 'id') INTO seq_name;
  SELECT MAX(id) FROM scheduled_session INTO max_id;

  IF seq_name IS NOT NULL THEN
    IF max_id IS NULL THEN
      -- table empty: set so nextval() returns 1
      PERFORM setval(seq_name, 1, false);
    ELSE
      -- table has rows: nextval() will return max_id+1
      PERFORM setval(seq_name, max_id, true);
    END IF;
  END IF;
END
$$;

COMMIT;
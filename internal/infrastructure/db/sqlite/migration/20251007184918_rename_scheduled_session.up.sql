-- 1) Create the new table (duration instead of round_interval)
CREATE TABLE IF NOT EXISTS scheduled_session (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   start_time INTEGER NOT NULL,
   end_time INTEGER NOT NULL,
   period INTEGER NOT NULL,
   duration INTEGER NOT NULL,
   updated_at INTEGER NOT NULL
);

-- 2) Copy rows from old table, ordered by id
INSERT INTO scheduled_session (id, start_time, end_time, period, duration, updated_at)
SELECT id, start_time, end_time, period, round_interval AS duration, updated_at
FROM market_hour
ORDER BY id ASC;

-- 3) Drop the old table
DROP TABLE market_hour;
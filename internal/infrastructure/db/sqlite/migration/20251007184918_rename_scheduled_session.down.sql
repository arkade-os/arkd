CREATE TABLE IF NOT EXISTS market_hour (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
   start_time INTEGER NOT NULL,
   end_time INTEGER NOT NULL,
   period INTEGER NOT NULL,
   round_interval INTEGER NOT NULL,
   updated_at INTEGER NOT NULL
);

INSERT INTO market_hour (id, start_time, end_time, period, round_interval, updated_at)
SELECT id, start_time, end_time, period, duration, updated_at
FROM scheduled_session
ORDER BY id ASC;

DROP TABLE scheduled_session;
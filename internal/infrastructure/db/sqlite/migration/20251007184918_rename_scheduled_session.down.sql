CREATE TABLE IF NOT EXISTS market_hour (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
   start_time INTEGER NOT NULL,
   end_time INTEGER NOT NULL,
   period INTEGER NOT NULL,
   round_interval INTEGER NOT NULL,
   round_min_participants INTEGER NOT NULL DEFAULT 0,
   round_max_participants INTEGER NOT NULL DEFAULT 0,
   updated_at INTEGER NOT NULL
);

INSERT INTO market_hour (id, start_time, end_time, period, round_interval, round_min_participants, round_max_participants, updated_at)
SELECT id, start_time, end_time, period, duration, round_min_participants, round_max_participants, updated_at
FROM scheduled_session
ORDER BY id ASC;

DROP TABLE scheduled_session;
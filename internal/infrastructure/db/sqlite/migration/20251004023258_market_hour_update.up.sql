ALTER TABLE market_hour ADD COLUMN round_min_participants INTEGER NOT NULL DEFAULT 0;
ALTER TABLE market_hour ADD COLUMN round_max_participants INTEGER NOT NULL DEFAULT 0;
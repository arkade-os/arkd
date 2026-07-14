-- Add velocity rate-limit settings. Defaults match the config defaults: disabled
-- by default so existing deployments keep their current behaviour after migrating.
ALTER TABLE settings ADD COLUMN rate_limit_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE settings ADD COLUMN rate_limit_max_velocity REAL NOT NULL DEFAULT 0.28;
ALTER TABLE settings ADD COLUMN rate_limit_max_cooldown_secs BIGINT NOT NULL DEFAULT 3600;

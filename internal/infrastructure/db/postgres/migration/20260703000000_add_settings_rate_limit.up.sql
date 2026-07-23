-- Add velocity rate-limit settings. Defaults match the config defaults: disabled
-- by default so existing deployments keep their current behaviour after migrating.
ALTER TABLE settings
    ADD COLUMN IF NOT EXISTS rate_limit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS rate_limit_max_velocity DOUBLE PRECISION NOT NULL DEFAULT 0.28,
    ADD COLUMN IF NOT EXISTS rate_limit_max_cooldown_secs BIGINT NOT NULL DEFAULT 3600;

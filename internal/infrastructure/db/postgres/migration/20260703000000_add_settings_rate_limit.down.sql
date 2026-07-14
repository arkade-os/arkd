ALTER TABLE settings
    DROP COLUMN IF EXISTS rate_limit_enabled,
    DROP COLUMN IF EXISTS rate_limit_max_velocity,
    DROP COLUMN IF EXISTS rate_limit_max_cooldown_secs;

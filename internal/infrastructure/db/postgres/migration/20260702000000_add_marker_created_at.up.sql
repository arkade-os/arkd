-- Add created_at to marker so the velocity rate limiter can measure how fast a
-- chain grows. Existing markers default to 0 (treated as very old, never limited).
ALTER TABLE marker
    ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;

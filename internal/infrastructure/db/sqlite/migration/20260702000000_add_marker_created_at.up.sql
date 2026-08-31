-- Add created_at to marker so the velocity rate limiter can measure how fast a
-- chain grows. Existing markers default to 0 (treated as very old, never limited).
ALTER TABLE marker ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;

ALTER TABLE settings ADD COLUMN epoch_expiry_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE settings ADD COLUMN epoch_anchor BIGINT NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN epoch_length BIGINT NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN rollover_window BIGINT NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN settlement_cutoff BIGINT NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN unroll_grace BIGINT NOT NULL DEFAULT 0;

-- 0 means "legacy batch": fall back to vtxo_tree_expiration, which is relative to
-- the round's ending timestamp. A non-zero value is the shared epoch date the
-- batch committed to, and must never be recomputed from the clock.
ALTER TABLE round ADD COLUMN epoch_expiry BIGINT NOT NULL DEFAULT 0;

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

-- The view is SELECT round.*, tx.* but its column list was fixed when it was
-- created, so ADD COLUMN above does not reach it. SelectExpiredRounds reads
-- epoch_expiry through this view, so it has to be rebuilt.
DROP VIEW IF EXISTS round_with_commitment_tx_vw;
CREATE VIEW round_with_commitment_tx_vw AS
SELECT round.*, tx.*
FROM round
INNER JOIN tx
ON round.id = tx.round_id AND tx.type = 'commitment';

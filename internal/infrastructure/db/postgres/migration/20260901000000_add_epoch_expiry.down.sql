DROP VIEW IF EXISTS round_with_commitment_tx_vw;

ALTER TABLE round DROP COLUMN epoch_expiry;

ALTER TABLE settings DROP COLUMN unroll_grace;
ALTER TABLE settings DROP COLUMN settlement_cutoff;
ALTER TABLE settings DROP COLUMN rollover_window;
ALTER TABLE settings DROP COLUMN epoch_length;
ALTER TABLE settings DROP COLUMN epoch_anchor;
ALTER TABLE settings DROP COLUMN epoch_expiry_enabled;

CREATE VIEW round_with_commitment_tx_vw AS
SELECT round.*, tx.*
FROM round
INNER JOIN tx
ON round.id = tx.round_id AND tx.type = 'commitment';

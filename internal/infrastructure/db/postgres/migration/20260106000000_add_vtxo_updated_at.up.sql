ALTER TABLE vtxo
ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT;

-- set existing null updated_at values to current timestamp
UPDATE vtxo
SET updated_at = (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
WHERE updated_at IS NULL;


-- update the vtxo_vw to include the new updated_at column
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;
CREATE VIEW vtxo_vw AS
SELECT v.*, string_agg(vc.commitment_txid, ',') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;


CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.*
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;
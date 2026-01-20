ALTER TABLE vtxo ADD COLUMN updated_at BIGINT;

-- set existing null updated_at values to current timestamp
UPDATE vtxo
SET updated_at = (CAST((strftime('%s','now') || substr(strftime('%f','now'),4,3)) AS INTEGER))
WHERE updated_at IS NULL;

-- update the vtxo_vw to include the new updated_at column
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;
CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;


CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.*
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;
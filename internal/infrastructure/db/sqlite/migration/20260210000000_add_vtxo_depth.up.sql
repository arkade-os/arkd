ALTER TABLE vtxo ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;

-- Recreate views to include the new depth column
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*,
       intent.id,
       intent.round_id,
       intent.proof,
       intent.message
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

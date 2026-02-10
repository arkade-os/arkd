-- Drop marker_id column from vtxo
DROP INDEX IF EXISTS idx_vtxo_marker_id;
ALTER TABLE vtxo DROP COLUMN IF EXISTS marker_id;

-- Drop marker tables
DROP TABLE IF EXISTS swept_marker;
DROP TABLE IF EXISTS marker;

-- Recreate views without marker_id
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT v.*, string_agg(vc.commitment_txid, ',') AS commitments
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

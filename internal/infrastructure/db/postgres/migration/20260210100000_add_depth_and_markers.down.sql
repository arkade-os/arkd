-- Drop views first (they depend on vtxo columns via v.*)
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Drop markers index and column from vtxo
DROP INDEX IF EXISTS idx_vtxo_markers;
ALTER TABLE vtxo DROP COLUMN IF EXISTS markers;

-- Drop depth column from vtxo
ALTER TABLE vtxo DROP COLUMN IF EXISTS depth;

-- Drop marker tables (indexes are dropped automatically with the table)
DROP TABLE IF EXISTS swept_marker;
DROP TABLE IF EXISTS marker;

-- Recreate views without depth and markers columns
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

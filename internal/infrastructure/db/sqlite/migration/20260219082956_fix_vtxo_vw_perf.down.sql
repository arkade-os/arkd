DROP INDEX IF EXISTS idx_asset_projection_vtxo;

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS round_intents_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT
  v.*,
  COALESCE((
    SELECT group_concat(commitment_txid, ',')
    FROM vtxo_commitment_txid
    WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
  ), '') AS commitments,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN (
  SELECT DISTINCT txid, vout, asset_id, amount
  FROM asset_projection
) AS ap
ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE VIEW round_intents_vw AS
SELECT intent.*
FROM round
LEFT OUTER JOIN intent
ON round.id=intent.round_id;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

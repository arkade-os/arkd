DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS round_intents_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT
  v.*,
  COALESCE((
    SELECT group_concat(vc.commitment_txid)
    FROM vtxo_commitment_txid vc
    WHERE vc.vtxo_txid = v.txid AND vc.vtxo_vout = v.vout
  ), '') AS commitments,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN (
  SELECT DISTINCT txid, vout, asset_id, amount
  FROM asset_projection
) AS ap ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT
  v.txid,
  v.vout,
  v.pubkey,
  v.amount,
  v.expires_at,
  v.created_at,
  v.commitment_txid,
  v.spent_by,
  v.spent,
  v.unrolled,
  v.swept,
  v.preconfirmed,
  v.settled_by,
  v.ark_txid,
  v.intent_id,
  v.updated_at,
  COALESCE((
    SELECT group_concat(vc.commitment_txid)
    FROM vtxo_commitment_txid vc
    WHERE vc.vtxo_txid = v.txid AND vc.vtxo_vout = v.vout
  ), '') AS commitments,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount,
  intent.id,
  intent.round_id,
  intent.proof,
  intent.message,
  intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo v ON intent.id = v.intent_id
LEFT JOIN asset_projection ap ON v.txid = ap.txid AND v.vout = ap.vout;

CREATE INDEX IF NOT EXISTS idx_asset_projection_vtxo ON asset_projection(txid, vout);

CREATE VIEW round_intents_vw AS
SELECT intent.*
FROM intent;

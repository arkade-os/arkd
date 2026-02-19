DROP VIEW IF EXISTS intent_with_inputs_vw;

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
  COALESCE(vc.commitments, '') AS commitments,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount,
  intent.id,
  intent.round_id,
  intent.proof,
  intent.message,
  intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo v ON intent.id = v.intent_id
LEFT JOIN LATERAL (
  SELECT string_agg(commitment_txid, ',') AS commitments
  FROM vtxo_commitment_txid
  WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
) vc ON true
LEFT JOIN (
  SELECT txid, vout, asset_id, amount
  FROM asset_projection
  GROUP BY txid, vout, asset_id, amount
) ap ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE INDEX IF NOT EXISTS idx_asset_projection_vtxo ON asset_projection(txid, vout);


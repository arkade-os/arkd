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
  v.preconfirmed,
  v.settled_by,
  v.ark_txid,
  v.intent_id,
  v.updated_at,
  v.depth,
  v.markers,
  COALESCE((
    SELECT group_concat(vc.commitment_txid)
    FROM vtxo_commitment_txid vc
    WHERE vc.vtxo_txid = v.txid AND vc.vtxo_vout = v.vout
  ), '') AS commitments,
  EXISTS (
    SELECT 1 FROM swept_marker sm
    JOIN json_each(v.markers) j ON j.value = sm.marker_id
  ) AS swept,
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

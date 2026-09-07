-- Reverse add_vtxo_kind: drop the views, drop the column, recreate the views
-- without vtxo_kind.
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

ALTER TABLE vtxo DROP COLUMN IF EXISTS vtxo_kind;

CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE(vc.commitments, '') AS commitments,
    (
        EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(v.markers) AS m(marker_id)
            JOIN swept_marker sm ON sm.marker_id = m.marker_id
        )
        OR EXISTS (
            SELECT 1 FROM swept_vtxo sv
            WHERE sv.txid = v.txid AND sv.vout = v.vout
        )
    ) AS swept,
    COALESCE(ap.asset_id, '') AS asset_id,
    COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN LATERAL (
    SELECT string_agg(commitment_txid, ',') AS commitments
    FROM vtxo_commitment_txid
    WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
) vc ON true
LEFT JOIN (
    SELECT txid, vout, asset_id, amount
    FROM asset_projection
    GROUP BY txid, vout, asset_id, amount
) ap
ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT
  v.txid, v.vout, v.pubkey, v.amount, v.expires_at, v.created_at,
  v.commitment_txid, v.spent_by, v.spent, v.unrolled, v.preconfirmed,
  v.settled_by, v.ark_txid, v.intent_id, v.updated_at, v.depth, v.markers,
  COALESCE(vc.commitments, '') AS commitments,
  (
      EXISTS (
          SELECT 1
          FROM jsonb_array_elements_text(v.markers) AS m(marker_id)
          JOIN swept_marker sm ON sm.marker_id = m.marker_id
      )
      OR EXISTS (
          SELECT 1 FROM swept_vtxo sv
          WHERE sv.txid = v.txid AND sv.vout = v.vout
      )
  ) AS swept,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount,
  intent.id, intent.round_id, intent.proof, intent.message,
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

-- asset_projection_pkey is PRIMARY KEY (asset_id, txid, vout), so the table is
-- already unique on (asset_id, txid, vout) and therefore on the wider tuple
-- (txid, vout, asset_id, amount). The GROUP BY over that tuple was a no-op on
-- row count, but it blocked the planner from probing asset_projection by
-- (txid, vout): PostgreSQL aggregated the whole table before joining, making
-- every vtxo_vw and intent_with_inputs_vw read O(asset_projection).
-- GetRoundWithCommitmentTxid measured 2.6-4.1s for a single round on a
-- production dump of ~236k rounds, ~113k VTXOs.
--
-- Joining asset_projection directly lets the planner use
-- idx_asset_projection_vtxo(txid, vout), added in 20260219082956.
-- Row output is unchanged: a VTXO holding several assets still yields one row
-- per asset, exactly as the GROUP BY form did.
--
-- This mirrors the SQLite migration
-- 20260925000000_inline_asset_projection_join.

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

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
LEFT JOIN asset_projection ap
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
LEFT JOIN asset_projection ap ON ap.txid = v.txid AND ap.vout = v.vout;

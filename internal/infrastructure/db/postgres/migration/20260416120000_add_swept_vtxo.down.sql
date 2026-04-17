-- Guard against silently resurrecting swept VTXOs.
--
-- swept_vtxo holds per-outpoint sweep state for the checkpoint-sweep path.
-- Dropping the table would make vtxo_vw.swept flip back to false for every
-- outpoint tracked only here (marker-based sweeps still survive via
-- swept_marker). When the table has data, fail loudly rather than silently
-- discard it. When the table is empty, the rollback is safe — drop the
-- table and restore the pre-swept_vtxo view shape.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM swept_vtxo) THEN
        RAISE EXCEPTION 'irreversible migration: swept_vtxo contains % entries; rolling back would resurrect swept VTXOs. Truncate swept_vtxo manually if you accept the data loss, then re-run.',
            (SELECT count(*) FROM swept_vtxo);
    END IF;
END
$$;

DROP TABLE IF EXISTS swept_vtxo;

-- Restore views without swept_vtxo check
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE(vc.commitments, '') AS commitments,
    EXISTS (
        SELECT 1 FROM swept_marker sm
        WHERE v.markers @> jsonb_build_array(sm.marker_id)
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
  EXISTS (
    SELECT 1 FROM swept_marker sm
    WHERE v.markers @> jsonb_build_array(sm.marker_id)
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

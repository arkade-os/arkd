-- Reverses the combined marker-DAG + swept migration.

-- Guard against silently resurrecting swept VTXOs. swept_vtxo holds per-outpoint
-- sweep state for batch and checkpoint sweeps; dropping it would flip
-- vtxo_vw.swept back to false for every outpoint tracked only there. Fail loudly
-- when it has data.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM swept_vtxo) THEN
        RAISE EXCEPTION 'irreversible migration: swept_vtxo contains % entries; rolling back would resurrect swept VTXOs. Truncate swept_vtxo manually if you accept the data loss, then re-run.',
            (SELECT count(*) FROM swept_vtxo);
    END IF;
END
$$;

-- Drop views first (they depend on vtxo columns via v.*)
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Restore the swept column that the up migration dropped. Backfill from
-- swept_marker (joined via the markers JSON array) before dropping the marker
-- tables, otherwise the rollback silently loses sweep state — VTXOs that were
-- swept via swept_marker would reappear as unswept. (swept_vtxo is empty per the
-- guard above, so it contributes nothing here.)
ALTER TABLE vtxo ADD COLUMN swept BOOLEAN NOT NULL DEFAULT false;
UPDATE vtxo v
SET swept = true
WHERE EXISTS (
    SELECT 1 FROM swept_marker sm
    WHERE v.markers @> jsonb_build_array(sm.marker_id)
);

-- Drop swept_vtxo (guaranteed empty by the guard above)
DROP TABLE IF EXISTS swept_vtxo;

-- Drop the checkpoint_tx index added by the up migration
DROP INDEX IF EXISTS idx_checkpoint_tx_offchain_txid;

-- Drop markers index and columns from vtxo
DROP INDEX IF EXISTS idx_vtxo_markers;
ALTER TABLE vtxo DROP COLUMN IF EXISTS markers;
ALTER TABLE vtxo DROP COLUMN IF EXISTS depth;

-- Drop marker tables (swept_marker FK -> marker, so swept_marker first)
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

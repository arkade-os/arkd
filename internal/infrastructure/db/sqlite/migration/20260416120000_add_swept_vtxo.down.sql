-- Guard against silently resurrecting swept VTXOs.
--
-- swept_vtxo holds per-outpoint sweep state for the checkpoint-sweep path.
-- Dropping the table would make vtxo_vw.swept flip back to false for every
-- outpoint tracked only here (marker-based sweeps still survive via
-- swept_marker). When the table has data, fail loudly rather than silently
-- discard it. When the table is empty, the rollback is safe — drop the
-- table and restore the pre-swept_vtxo view shape.
--
-- SQLite has no RAISE outside of triggers, so we route through a trigger on
-- a throwaway temp table. The conditional INSERT fires the trigger only when
-- swept_vtxo has at least one row; otherwise it's a no-op and we fall through
-- to the drop + view recreation.
CREATE TEMP TABLE __abort_swept_vtxo_down (x INTEGER);
CREATE TEMP TRIGGER __abort_swept_vtxo_down_trigger BEFORE INSERT ON __abort_swept_vtxo_down
BEGIN
    SELECT RAISE(ABORT, 'irreversible migration: swept_vtxo contains entries; rolling back would resurrect swept VTXOs. Truncate swept_vtxo manually if you accept the data loss, then re-run.');
END;
INSERT INTO __abort_swept_vtxo_down SELECT 1 FROM swept_vtxo LIMIT 1;
DROP TRIGGER __abort_swept_vtxo_down_trigger;
DROP TABLE __abort_swept_vtxo_down;

DROP TABLE IF EXISTS swept_vtxo;

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE((
        SELECT group_concat(commitment_txid, ',')
        FROM vtxo_commitment_txid
        WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
    ), '') AS commitments,
    EXISTS (
        SELECT 1 FROM swept_marker sm
        JOIN json_each(v.markers) j ON j.value = sm.marker_id
    ) AS swept,
    COALESCE(ap.asset_id, '') AS asset_id,
    COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN (
    SELECT DISTINCT txid, vout, asset_id, amount
    FROM asset_projection
) AS ap
ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

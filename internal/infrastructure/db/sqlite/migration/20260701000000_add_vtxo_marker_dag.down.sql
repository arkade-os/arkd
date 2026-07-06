-- Reverses the combined marker-DAG + swept migration.

-- Guard against silently resurrecting swept VTXOs. swept_vtxo holds per-outpoint
-- checkpoint-sweep state; dropping it would flip swept back to false for every
-- outpoint tracked only there. SQLite has no RAISE outside triggers, so route
-- through a trigger on a throwaway temp table: the conditional INSERT fires only
-- when swept_vtxo has at least one row; otherwise it is a no-op and we fall through.
CREATE TEMP TABLE __abort_swept_vtxo_down (x INTEGER);
CREATE TEMP TRIGGER __abort_swept_vtxo_down_trigger BEFORE INSERT ON __abort_swept_vtxo_down
BEGIN
    SELECT RAISE(ABORT, 'irreversible migration: swept_vtxo contains entries; rolling back would resurrect swept VTXOs. Truncate swept_vtxo manually if you accept the data loss, then re-run.');
END;
INSERT INTO __abort_swept_vtxo_down SELECT 1 FROM swept_vtxo LIMIT 1;
DROP TRIGGER __abort_swept_vtxo_down_trigger;
DROP TABLE __abort_swept_vtxo_down;

DROP TABLE IF EXISTS swept_vtxo;

-- SQLite doesn't support DROP COLUMN directly, so recreate the table to restore the
-- swept column and drop depth/markers. Compute swept from swept_marker (before the
-- marker tables are dropped) so sweep state survives the rollback. swept_vtxo is
-- empty per the guard above, so it contributes nothing here.
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE TABLE vtxo_temp (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    amount INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    commitment_txid TEXT NOT NULL,
    spent_by TEXT,
    spent BOOLEAN NOT NULL DEFAULT FALSE,
    unrolled BOOLEAN NOT NULL DEFAULT FALSE,
    swept BOOLEAN NOT NULL DEFAULT FALSE,
    preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
    settled_by TEXT,
    ark_txid TEXT,
    intent_id TEXT,
    updated_at INTEGER,
    PRIMARY KEY (txid, vout),
    FOREIGN KEY (intent_id) REFERENCES intent(id)
);

-- Copy data, computing swept from swept_marker since the column was removed in the up migration
INSERT INTO vtxo_temp SELECT
    v.txid, v.vout, v.pubkey, v.amount, v.expires_at, v.created_at, v.commitment_txid,
    v.spent_by, v.spent, v.unrolled,
    EXISTS (
        SELECT 1 FROM swept_marker sm
        JOIN json_each(v.markers) j ON j.value = sm.marker_id
    ) AS swept,
    v.preconfirmed, v.settled_by, v.ark_txid,
    v.intent_id, v.updated_at
FROM vtxo v;

-- Drop old table and rename
DROP TABLE vtxo;
ALTER TABLE vtxo_temp RENAME TO vtxo;

-- Recreate indexes. Restore idx_vtxo_pubkey_updated_at too: this migration runs after
-- 20260318074028_vtxo_indexes, so the rollback must not leave the DB missing that index.
CREATE INDEX IF NOT EXISTS fk_vtxo_intent_id ON vtxo(intent_id);
CREATE INDEX IF NOT EXISTS idx_vtxo_pubkey_updated_at
    ON vtxo (pubkey, updated_at);

-- Drop the checkpoint_tx index added by the up migration
DROP INDEX IF EXISTS idx_checkpoint_tx_offchain_txid;

-- Drop marker tables
DROP TABLE IF EXISTS swept_marker;
DROP TABLE IF EXISTS marker;

-- Recreate views without depth and markers columns
CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
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

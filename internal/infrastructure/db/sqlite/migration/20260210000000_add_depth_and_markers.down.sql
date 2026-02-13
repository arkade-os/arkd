-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Create temp table without depth and markers columns
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
        WHERE v.markers LIKE '%"' || sm.marker_id || '"%'
    ) AS swept,
    v.preconfirmed, v.settled_by, v.ark_txid,
    v.intent_id, v.updated_at
FROM vtxo v;

-- Drop old table and rename
DROP TABLE vtxo;
ALTER TABLE vtxo_temp RENAME TO vtxo;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS fk_vtxo_intent_id ON vtxo(intent_id);

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

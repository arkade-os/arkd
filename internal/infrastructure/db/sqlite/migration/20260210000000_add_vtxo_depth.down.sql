-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
-- This migration creates a new table without the depth column and copies data

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE TABLE vtxo_new (
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
    updated_at BIGINT,
    PRIMARY KEY (txid, vout),
    FOREIGN KEY (intent_id) REFERENCES intent(id)
);

INSERT INTO vtxo_new (txid, vout, pubkey, amount, expires_at, created_at, commitment_txid, spent_by, spent, unrolled, swept, preconfirmed, settled_by, ark_txid, intent_id, updated_at)
SELECT txid, vout, pubkey, amount, expires_at, created_at, commitment_txid, spent_by, spent, unrolled, swept, preconfirmed, settled_by, ark_txid, intent_id, updated_at
FROM vtxo;

DROP TABLE vtxo;
ALTER TABLE vtxo_new RENAME TO vtxo;

-- Recreate foreign key index
CREATE INDEX IF NOT EXISTS fk_vtxo_intent_id ON vtxo(intent_id);

-- Recreate views without depth column
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

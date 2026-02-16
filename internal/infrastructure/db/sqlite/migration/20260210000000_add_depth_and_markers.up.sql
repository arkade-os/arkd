-- Add depth column
ALTER TABLE vtxo ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;

-- Create marker table
CREATE TABLE IF NOT EXISTS marker (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    parent_markers TEXT  -- JSON array of parent marker IDs
);
CREATE INDEX IF NOT EXISTS idx_marker_depth ON marker(depth);

-- Create swept_marker table (append-only)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at INTEGER NOT NULL
);

-- Add markers column (JSON array, not single marker_id)
ALTER TABLE vtxo ADD COLUMN markers TEXT;
CREATE INDEX IF NOT EXISTS idx_vtxo_markers ON vtxo(markers);

-- Recreate views to include the new columns
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT
  v.*,
  COALESCE((
    SELECT group_concat(commitment_txid, ',')
    FROM vtxo_commitment_txid
    WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
  ), '') AS commitments,
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

-- Backfill: Create a marker for every existing VTXO using its outpoint as marker ID
-- This ensures every VTXO has at least 1 marker
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout,
    v.depth,
    '[]'
FROM vtxo v;

-- Assign the marker to every VTXO
UPDATE vtxo SET markers = '["' || txid || ':' || vout || '"]';

-- Migrate existing swept VTXOs to swept_marker table before dropping column
-- Insert the VTXO's marker into swept_marker
INSERT OR IGNORE INTO swept_marker (marker_id, swept_at)
SELECT
    v.txid || ':' || v.vout,
    strftime('%s', 'now')
FROM vtxo v
WHERE v.swept = 1;

-- SQLite doesn't support DROP COLUMN easily, so we recreate the table
-- Create new vtxo table without swept column
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
    preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
    settled_by TEXT,
    ark_txid TEXT,
    intent_id TEXT,
    updated_at INTEGER,
    depth INTEGER NOT NULL DEFAULT 0,
    markers TEXT,
    PRIMARY KEY (txid, vout),
    FOREIGN KEY (intent_id) REFERENCES intent(id)
);

-- Copy data from old table (excluding swept column)
INSERT INTO vtxo_new (txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
    spent_by, spent, unrolled, preconfirmed, settled_by, ark_txid, intent_id, updated_at, depth, markers)
SELECT txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
    spent_by, spent, unrolled, preconfirmed, settled_by, ark_txid, intent_id, updated_at, depth, markers
FROM vtxo;

-- Drop old views that depend on vtxo
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Drop old table and rename new one
DROP TABLE vtxo;
ALTER TABLE vtxo_new RENAME TO vtxo;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS fk_vtxo_intent_id ON vtxo(intent_id);
CREATE INDEX IF NOT EXISTS idx_vtxo_markers ON vtxo(markers);

-- Recreate views to compute swept status dynamically
CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE((
        SELECT group_concat(commitment_txid, ',')
        FROM vtxo_commitment_txid
        WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
    ), '') AS commitments,
    EXISTS (
        SELECT 1 FROM swept_marker sm
        WHERE v.markers LIKE '%"' || sm.marker_id || '"%'
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

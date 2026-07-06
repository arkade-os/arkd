-- Marker-DAG + swept tracking schema. This migration merges what were previously
-- two migrations (add_depth_and_markers then add_swept_vtxo); they were only ever
-- deployed together, so combining them builds the final views once instead of
-- rebuilding them twice.

-- Add depth column
ALTER TABLE vtxo ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;

-- Create marker table
CREATE TABLE IF NOT EXISTS marker (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    parent_markers TEXT  -- JSON array of parent marker IDs
);
CREATE INDEX IF NOT EXISTS idx_marker_depth ON marker(depth);

-- Create swept_marker table (append-only, populated by batch/round sweeps)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at INTEGER NOT NULL
);

-- Create swept_vtxo table (per-outpoint sweep tracking for checkpoint sweeps)
CREATE TABLE IF NOT EXISTS swept_vtxo (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    swept_at INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);

-- Index to accelerate the bulk offchain tx query's join on checkpoint_tx
CREATE INDEX IF NOT EXISTS idx_checkpoint_tx_offchain_txid
    ON checkpoint_tx (offchain_txid);

-- Add markers column (JSON array, not single marker_id)
ALTER TABLE vtxo ADD COLUMN markers TEXT NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_vtxo_markers ON vtxo(markers);

-- Backfill: create a marker for every existing VTXO using its outpoint as marker ID
-- NOTE: this INSERT and the UPDATE below run over all VTXOs and will hold locks.
-- On large production DBs (millions of rows) expect 10-60 seconds; plan a maintenance window.
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout,
    v.depth,
    '[]'
FROM vtxo v;

-- Assign the marker to every VTXO
UPDATE vtxo SET markers = '["' || txid || ':' || vout || '"]';

-- Migrate existing swept VTXOs into swept_marker before dropping the swept column
INSERT OR IGNORE INTO swept_marker (marker_id, swept_at)
SELECT
    v.txid || ':' || v.vout,
    strftime('%s', 'now') * 1000
FROM vtxo v
WHERE v.swept = 1;

-- SQLite doesn't support DROP COLUMN easily, so recreate the table without swept.
-- Drop views that depend on vtxo first.
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
    preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
    settled_by TEXT,
    ark_txid TEXT,
    intent_id TEXT,
    updated_at INTEGER,
    depth INTEGER NOT NULL DEFAULT 0,
    markers TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (txid, vout),
    FOREIGN KEY (intent_id) REFERENCES intent(id)
);

-- Copy data from old table (excluding swept column)
INSERT INTO vtxo_new (txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
    spent_by, spent, unrolled, preconfirmed, settled_by, ark_txid, intent_id, updated_at, depth, markers)
SELECT txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
    spent_by, spent, unrolled, preconfirmed, settled_by, ark_txid, intent_id, updated_at, depth, markers
FROM vtxo;

-- Drop old table and rename new one
DROP TABLE vtxo;
ALTER TABLE vtxo_new RENAME TO vtxo;

-- Recreate indexes. Re-timestamped above prod HEAD, this migration now runs after
-- 20260318074028_vtxo_indexes, so the table rebuild above drops that index; restore it
-- here to keep the final schema identical regardless of apply order.
CREATE INDEX IF NOT EXISTS fk_vtxo_intent_id ON vtxo(intent_id);
CREATE INDEX IF NOT EXISTS idx_vtxo_pubkey_updated_at
    ON vtxo (pubkey, updated_at);

-- Build the final views. swept is OR'd across two sources on purpose:
--   * swept_marker — batch/round sweeps. Coarse: one marker can cover many VTXOs.
--   * swept_vtxo   — checkpoint sweeps. Fine: one row per (txid, vout).
CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE((
        SELECT group_concat(commitment_txid, ',')
        FROM vtxo_commitment_txid
        WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
    ), '') AS commitments,
    (
        EXISTS (
            SELECT 1 FROM swept_marker sm
            JOIN json_each(v.markers) j ON j.value = sm.marker_id
        )
        OR EXISTS (
            SELECT 1 FROM swept_vtxo sv
            WHERE sv.txid = v.txid AND sv.vout = v.vout
        )
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
  (
      EXISTS (
          SELECT 1 FROM swept_marker sm
          JOIN json_each(v.markers) j ON j.value = sm.marker_id
      )
      OR EXISTS (
          SELECT 1 FROM swept_vtxo sv
          WHERE sv.txid = v.txid AND sv.vout = v.vout
      )
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

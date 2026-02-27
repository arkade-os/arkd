-- Add depth and markers columns to vtxo
ALTER TABLE vtxo
    ADD COLUMN IF NOT EXISTS depth INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS markers JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS idx_vtxo_markers ON vtxo USING GIN (markers);

-- Create marker table
CREATE TABLE IF NOT EXISTS marker (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    parent_markers JSONB  -- JSON array of parent marker IDs
);
CREATE INDEX IF NOT EXISTS idx_marker_depth ON marker(depth);
CREATE INDEX IF NOT EXISTS idx_marker_parent_markers ON marker USING GIN (parent_markers);

-- Create swept_marker table (append-only)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at BIGINT NOT NULL
);

-- Recreate views to include the new columns
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT
  v.*,
  COALESCE(vc.commitments, '') AS commitments,
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
    '[]'::jsonb
FROM vtxo v;

-- Assign the marker to every VTXO
UPDATE vtxo SET markers = jsonb_build_array(txid || ':' || vout);

-- Migrate existing swept VTXOs to swept_marker table before dropping column
-- Insert the VTXO's marker into swept_marker
INSERT INTO swept_marker (marker_id, swept_at)
SELECT
    v.txid || ':' || v.vout,
    EXTRACT(EPOCH FROM NOW())::BIGINT
FROM vtxo v
WHERE v.swept = true
ON CONFLICT (marker_id) DO NOTHING;

-- Drop views before dropping the swept column (views depend on it via v.*)
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Drop swept column from vtxo table (swept state now computed via markers)
ALTER TABLE vtxo DROP COLUMN IF EXISTS swept;

-- Recreate views to compute swept status dynamically

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
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

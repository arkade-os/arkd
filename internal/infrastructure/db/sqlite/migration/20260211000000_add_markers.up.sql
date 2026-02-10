-- Create markers table
CREATE TABLE IF NOT EXISTS marker (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    parent_markers TEXT  -- JSON array of parent marker IDs
);
CREATE INDEX IF NOT EXISTS idx_marker_depth ON marker(depth);

-- Create swept_markers table (append-only)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at INTEGER NOT NULL
);

-- Add marker_id column to vtxo table
ALTER TABLE vtxo ADD COLUMN marker_id TEXT REFERENCES marker(id);
CREATE INDEX IF NOT EXISTS idx_vtxo_marker_id ON vtxo(marker_id);

-- Recreate views to include the new marker_id column
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

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

-- Backfill markers for existing VTXOs based on their depth
-- VTXOs at depth 0, 100, 200, ... get their own markers
-- Other VTXOs will have their marker_id set during PR 5 (marker assignment logic)

-- First, create markers for all existing VTXOs at marker boundary depths (depth % 100 == 0)
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout,  -- Use VTXO outpoint as marker ID
    v.depth,
    '[]'  -- Empty parent markers for initial backfill
FROM vtxo v
WHERE v.depth % 100 = 0;

-- Assign marker_id to VTXOs at boundary depths
UPDATE vtxo
SET marker_id = txid || ':' || vout
WHERE depth % 100 = 0;

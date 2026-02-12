-- Add depth and markers columns to vtxo
ALTER TABLE vtxo
    ADD COLUMN IF NOT EXISTS depth INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS markers JSONB;
CREATE INDEX IF NOT EXISTS idx_vtxo_markers ON vtxo USING GIN (markers);

-- Create marker table
CREATE TABLE IF NOT EXISTS marker (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    parent_markers JSONB  -- JSON array of parent marker IDs
);
CREATE INDEX IF NOT EXISTS idx_marker_depth ON marker(depth);

-- Create swept_marker table (append-only)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at BIGINT NOT NULL
);

-- Recreate views to include the new columns
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

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

-- Backfill markers for existing VTXOs based on their depth
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout,
    v.depth,
    '[]'::jsonb
FROM vtxo v
WHERE v.depth % 100 = 0;

-- Assign markers array to VTXOs at boundary depths
UPDATE vtxo SET markers = jsonb_build_array(txid || ':' || vout)
WHERE depth % 100 = 0;

-- Migrate existing swept VTXOs to swept_marker table before dropping column
-- For each swept VTXO, create a unique dust marker and insert into swept_marker
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout || ':dust',
    v.depth,
    COALESCE(v.markers, '[]'::jsonb)
FROM vtxo v
WHERE v.swept = true
ON CONFLICT (id) DO NOTHING;

INSERT INTO swept_marker (marker_id, swept_at)
SELECT
    v.txid || ':' || v.vout || ':dust',
    EXTRACT(EPOCH FROM NOW())::BIGINT
FROM vtxo v
WHERE v.swept = true
ON CONFLICT (marker_id) DO NOTHING;

-- Update swept VTXOs to include the dust marker in their markers array
UPDATE vtxo SET markers = COALESCE(markers, '[]'::jsonb) || jsonb_build_array(txid || ':' || vout || ':dust')
WHERE swept = true;

-- Drop views before dropping the swept column (views depend on it via v.*)
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Drop swept column from vtxo table (swept state now computed via markers)
ALTER TABLE vtxo DROP COLUMN IF EXISTS swept;

-- Recreate views to compute swept status dynamically

CREATE VIEW vtxo_vw AS
SELECT v.*,
    string_agg(vc.commitment_txid, ',') AS commitments,
    EXISTS (
        SELECT 1 FROM swept_marker sm
        WHERE v.markers @> jsonb_build_array(sm.marker_id)
    ) AS swept
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

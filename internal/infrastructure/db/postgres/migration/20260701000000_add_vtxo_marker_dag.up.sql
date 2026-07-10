-- Marker-DAG + swept tracking schema. 
--
-- Adds vtxo.depth / vtxo.markers, the marker / swept_marker / swept_vtxo tables,
-- the checkpoint_tx(offchain_txid) index, gives every existing vtxo a self-marker,
-- migrates the old vtxo.swept column into swept_marker, drops the column, and computes
-- swept dynamically in the views.

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

-- Create swept_marker table (append-only, written with self-markers by the
-- legacy-swept migration below and by dust-vtxo sweeps)
CREATE TABLE IF NOT EXISTS swept_marker (
    marker_id TEXT PRIMARY KEY REFERENCES marker(id),
    swept_at BIGINT NOT NULL
);

-- Create swept_vtxo table (per-outpoint sweep tracking for batch and checkpoint sweeps)
CREATE TABLE IF NOT EXISTS swept_vtxo (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    swept_at BIGINT NOT NULL,
    PRIMARY KEY (txid, vout)
);

-- Index to accelerate the bulk offchain tx query's join on checkpoint_tx
CREATE INDEX IF NOT EXISTS idx_checkpoint_tx_offchain_txid
    ON checkpoint_tx (offchain_txid);

-- Backfill: create a marker for every existing VTXO using its outpoint as marker ID
-- so every VTXO has at least one marker.
-- NOTE: this INSERT and the UPDATE below run over all VTXOs and will hold locks.
-- On large production DBs (millions of rows) expect 10-60 seconds; plan a maintenance window.
INSERT INTO marker (id, depth, parent_markers)
SELECT
    v.txid || ':' || v.vout,
    v.depth,
    '[]'::jsonb
FROM vtxo v;

-- Assign the marker to every VTXO
UPDATE vtxo SET markers = jsonb_build_array(txid || ':' || vout);

-- Migrate existing swept VTXOs into swept_marker before dropping the swept column
INSERT INTO swept_marker (marker_id, swept_at)
SELECT
    v.txid || ':' || v.vout,
    (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
FROM vtxo v
WHERE v.swept = true
ON CONFLICT (marker_id) DO NOTHING;

-- Drop old views before dropping the swept column (views depend on it via v.*)
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- Drop swept column from vtxo (swept state now computed via markers / swept_vtxo)
ALTER TABLE vtxo DROP COLUMN IF EXISTS swept;

-- Build the final views. swept is OR'd across two sources on purpose:
--   * swept_marker — self-marker records (legacy migrated sweeps, dust vtxos).
--   * swept_vtxo   — batch and checkpoint sweeps. One row per (txid, vout).
-- The swept lookup unnests v.markers and probes swept_marker_pkey per marker_id.
-- The earlier `markers @> jsonb_build_array(sm.marker_id)` form forced a seq scan
-- of swept_marker per outer row (the GIN index on vtxo.markers is on the wrong side
-- of the @> operator), making every vtxo_vw read O(swept_marker).
CREATE VIEW vtxo_vw AS
SELECT v.*,
    COALESCE(vc.commitments, '') AS commitments,
    (
        EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(v.markers) AS m(marker_id)
            JOIN swept_marker sm ON sm.marker_id = m.marker_id
        )
        OR EXISTS (
            SELECT 1 FROM swept_vtxo sv
            WHERE sv.txid = v.txid AND sv.vout = v.vout
        )
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
SELECT
  v.txid, v.vout, v.pubkey, v.amount, v.expires_at, v.created_at,
  v.commitment_txid, v.spent_by, v.spent, v.unrolled, v.preconfirmed,
  v.settled_by, v.ark_txid, v.intent_id, v.updated_at, v.depth, v.markers,
  COALESCE(vc.commitments, '') AS commitments,
  (
      EXISTS (
          SELECT 1
          FROM jsonb_array_elements_text(v.markers) AS m(marker_id)
          JOIN swept_marker sm ON sm.marker_id = m.marker_id
      )
      OR EXISTS (
          SELECT 1 FROM swept_vtxo sv
          WHERE sv.txid = v.txid AND sv.vout = v.vout
      )
  ) AS swept,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount,
  intent.id, intent.round_id, intent.proof, intent.message,
  intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo v ON intent.id = v.intent_id
LEFT JOIN LATERAL (
  SELECT string_agg(commitment_txid, ',') AS commitments
  FROM vtxo_commitment_txid
  WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
) vc ON true
LEFT JOIN (
  SELECT txid, vout, asset_id, amount
  FROM asset_projection
  GROUP BY txid, vout, asset_id, amount
) ap ON ap.txid = v.txid AND ap.vout = v.vout;

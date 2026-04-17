-- Per-outpoint sweep tracking for checkpoint sweeps (see Postgres migration).
CREATE TABLE IF NOT EXISTS swept_vtxo (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    swept_at INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);

-- Rebuild vtxo_vw: swept if marker in swept_marker OR outpoint in swept_vtxo
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

-- swept is OR'd across two sources on purpose:
--   * swept_marker — populated by batch/round sweeps. Coarse-grained: a single
--     marker can cover many VTXOs, so marker-based sweeping is efficient for
--     whole-round sweeps but would over-reach if applied to checkpoint sweeps
--     (markers are shared across independent subtrees).
--   * swept_vtxo — populated by checkpoint sweeps. Fine-grained: one row per
--     (txid, vout), so it safely scopes to a single outpoint's lineage.
-- New sweep code paths must pick the right table; maintainers adding a third
-- sweep path should extend this OR rather than re-overloading one of them.
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

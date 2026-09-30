-- The asset_projection primary key already makes (txid, vout, asset_id, amount)
-- unique. DISTINCT forced SQLite to materialize the entire projection table for
-- each filtered GetVtxos request, instead of probing by (txid, vout).
DROP VIEW IF EXISTS vtxo_vw;

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
LEFT JOIN asset_projection ap
ON ap.txid = v.txid AND ap.vout = v.vout;

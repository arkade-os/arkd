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
LEFT JOIN (
    SELECT DISTINCT txid, vout, asset_id, amount
    FROM asset_projection
) AS ap
ON ap.txid = v.txid AND ap.vout = v.vout;

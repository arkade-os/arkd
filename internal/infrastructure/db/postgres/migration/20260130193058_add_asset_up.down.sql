DROP TABLE IF EXISTS asset_metadata_update;
DROP TABLE IF EXISTS asset_projection;
DROP TABLE IF EXISTS asset;

DROP VIEW IF EXISTS vtxo_vw;
CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(string_agg(vc.commitment_txid, ','), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

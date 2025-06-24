CREATE TABLE vtxo_commitment_txid (
    vtxo_txid TEXT NOT NULL,
    vtxo_vout INTEGER NOT NULL,
    commitment_txid TEXT NOT NULL,
    PRIMARY KEY (vtxo_txid, vtxo_vout, commitment_txid),
    FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxo(txid, vout)
);

CREATE VIEW IF NOT EXISTS vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

DROP VIEW IF EXISTS request_vtxo_vw;

CREATE VIEW IF NOT EXISTS request_vtxo_vw AS
SELECT vtxo_vw.*
FROM tx_request
LEFT OUTER JOIN vtxo_vw
ON tx_request.id = vtxo_vw.request_id;
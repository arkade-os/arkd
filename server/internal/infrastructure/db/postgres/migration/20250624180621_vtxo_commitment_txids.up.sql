CREATE TABLE vtxo_commitment_txid (
    vtxo_txid VARCHAR NOT NULL,
    vtxo_vout INTEGER NOT NULL,
    commitment_txid VARCHAR NOT NULL,
    PRIMARY KEY (vtxo_txid, vtxo_vout, commitment_txid),
    FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxo(txid, vout)
);

CREATE VIEW vtxo_vw AS
SELECT v.*, string_agg(vc.commitment_txid, ',') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

DROP VIEW request_vtxo_vw;
CREATE VIEW request_vtxo_vw AS
SELECT vtxo_vw.*
FROM tx_request
LEFT OUTER JOIN vtxo_vw
ON tx_request.id = vtxo_vw.request_id;

DROP VIEW vtxo_virtual_tx_vw;
CREATE VIEW vtxo_virtual_tx_vw AS
SELECT
    vtxo_vw.*,
    virtual_tx.tx AS redeem_tx
FROM vtxo_vw
LEFT JOIN virtual_tx
ON vtxo_vw.txid = virtual_tx.txid;
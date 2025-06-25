DROP TABLE vtxo_commitment_txid;

DROP VIEW vtxo_vw;

DROP VIEW request_vtxo_vw;
CREATE VIEW request_vtxo_vw AS
SELECT vtxo.*
FROM tx_request
LEFT OUTER JOIN vtxo
ON tx_request.id = vtxo.request_id;

DROP VIEW vtxo_virtual_tx_vw;
CREATE VIEW vtxo_virtual_tx_vw AS
SELECT
    vtxo.*,
    virtual_tx.tx AS redeem_tx
FROM vtxo
LEFT JOIN virtual_tx
ON vtxo.txid = virtual_tx.txid;
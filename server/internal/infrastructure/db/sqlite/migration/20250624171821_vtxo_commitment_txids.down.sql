DROP TABLE vtxo_commitment_txid;

DROP VIEW IF EXISTS vtxo_vw;

DROP VIEW IF EXISTS request_vtxo_vw;

CREATE VIEW IF NOT EXISTS request_vtxo_vw AS
SELECT vtxo.*
FROM tx_request
LEFT OUTER JOIN vtxo
ON tx_request.id = vtxo.request_id;
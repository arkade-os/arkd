ALTER TABLE tx_request DROP COLUMN;
ALTER TABLE tx_request DROP COLUMN;

CREATE OR REPLACE VIEW round_request_vw AS
SELECT tx_request.*
FROM round
LEFT OUTER JOIN tx_request
ON round.id=tx_request.round_id;

CREATE OR REPLACE VIEW request_receiver_vw AS
SELECT receiver.*
FROM tx_request
LEFT OUTER JOIN receiver
ON tx_request.id=receiver.request_id;

CREATE OR REPLACE VIEW request_vtxo_vw AS
SELECT vtxo_vw.*
FROM tx_request
LEFT OUTER JOIN vtxo_vw
ON tx_request.id = vtxo_vw.request_id;

CREATE OR REPLACE VIEW vtxo_virtual_tx_vw AS
SELECT
    vtxo_vw.*,
    virtual_tx.tx AS redeem_tx
FROM vtxo_vw
LEFT JOIN virtual_tx
ON vtxo_vw.txid = virtual_tx.txid;
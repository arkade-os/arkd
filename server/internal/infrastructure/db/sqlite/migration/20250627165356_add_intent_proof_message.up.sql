DROP VIEW IF EXISTS round_request_vw;
DROP VIEW IF EXISTS request_receiver_vw;
DROP VIEW IF EXISTS request_vtxo_vw;

ALTER TABLE tx_request ADD COLUMN proof TEXT NOT NULL;
ALTER TABLE tx_request ADD COLUMN message TEXT NOT NULL;

CREATE VIEW IF NOT EXISTS round_request_vw AS
SELECT tx_request.*
FROM round
LEFT OUTER JOIN tx_request
ON round.id=tx_request.round_id;

CREATE VIEW IF NOT EXISTS request_receiver_vw AS
SELECT receiver.*, tx_request.*
FROM tx_request
LEFT OUTER JOIN receiver
ON tx_request.id=receiver.request_id;

CREATE VIEW IF NOT EXISTS request_vtxo_vw AS
SELECT vtxo_vw.*, tx_request.*
FROM tx_request
LEFT OUTER JOIN vtxo_vw
ON tx_request.id = vtxo_vw.request_id;
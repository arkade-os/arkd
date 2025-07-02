DROP VIEW IF EXISTS round_request_vw;
DROP VIEW IF EXISTS request_receiver_vw;
DROP VIEW IF EXISTS request_vtxo_vw;
DROP VIEW IF EXISTS vtxo_vw;

ALTER TABLE tx_request ADD COLUMN proof TEXT NOT NULL;
ALTER TABLE tx_request ADD COLUMN message TEXT NOT NULL;
ALTER TABLE vtxo ADD COLUMN settled_by TEXT;
ALTER TABLE vtxo DROP COLUMN redeem_tx;
ALTER TABLE vtxo ADD COLUMN preconfirmed BOOLEAN NOT NULL;
ALTER TABLE vtxo ADD COLUMN ark_txid TEXT;
ALTER TABLE vtxo DROP COLUMN spent_by;
ALTER TABLE vtxo ADD COLUMN spent_by TEXT;

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

CREATE VIEW IF NOT EXISTS vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

CREATE VIEW IF NOT EXISTS request_vtxo_vw AS
SELECT vtxo_vw.*, tx_request.*
FROM tx_request
LEFT OUTER JOIN vtxo_vw
ON tx_request.id = vtxo_vw.request_id;
ALTER TABLE intent ADD COLUMN txid TEXT;

DROP VIEW IF EXISTS round_intents_vw;
DROP VIEW IF EXISTS intent_with_receivers_vw;
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW round_intents_vw AS
SELECT intent.*
FROM round
LEFT OUTER JOIN intent
ON round.id=intent.round_id;

CREATE VIEW intent_with_receivers_vw AS
SELECT receiver.*, intent.*
FROM intent
LEFT OUTER JOIN receiver
ON intent.id=receiver.intent_id;

CREATE VIEW vtxo_vw AS
SELECT v.*, string_agg(vc.commitment_txid, ',') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;
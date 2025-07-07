DROP INDEX IF EXISTS fk_intent_round_id;
DROP INDEX IF EXISTS fk_tx_round_id;
DROP INDEX IF EXISTS fk_receiver_intent_id;
DROP INDEX IF EXISTS fk_vtxo_intent_id;

DROP VIEW IF EXISTS vtxo_vw;
DROP VIEW IF EXISTS round_intents_vw;
DROP VIEW IF EXISTS round_txs_vw;
DROP VIEW IF EXISTS round_with_commitment_tx_vw;
DROP VIEW IF EXISTS intent_with_receivers_vw;
DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS offchain_tx_vw;

DROP TABLE IF EXISTS round;
DROP TABLE IF EXISTS intent;
DROP TABLE IF EXISTS receiver;
DROP TABLE IF EXISTS tx;
DROP TABLE IF EXISTS vtxo;
DROP TABLE IF EXISTS vtxo_commitment_txid;
DROP TABLE IF EXISTS offchain_tx;
DROP TABLE IF EXISTS checkpoint_tx;
DROP TABLE IF EXISTS market_hour;
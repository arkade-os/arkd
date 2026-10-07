DROP TRIGGER IF EXISTS utxo_pointer_must_be_unrolled_vtxo;
DROP TRIGGER IF EXISTS utxo_must_not_duplicate_vtxo;
DROP VIEW IF EXISTS utxo_vw;
DROP TABLE IF EXISTS utxo;
DROP TABLE IF EXISTS onchain_tx;
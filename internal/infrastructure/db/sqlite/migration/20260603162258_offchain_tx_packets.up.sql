ALTER TABLE offchain_tx ADD COLUMN packets TEXT;

DROP VIEW IF EXISTS offchain_tx_vw;
CREATE VIEW offchain_tx_vw AS
SELECT
    offchain_tx.*,
    COALESCE(checkpoint_tx.txid, '') AS checkpoint_txid,
    COALESCE(checkpoint_tx.tx, '') AS checkpoint_tx,
    checkpoint_tx.commitment_txid,
    checkpoint_tx.is_root_commitment_txid,
    checkpoint_tx.offchain_txid
FROM offchain_tx
    LEFT JOIN checkpoint_tx
    ON offchain_tx.txid = checkpoint_tx.offchain_txid;

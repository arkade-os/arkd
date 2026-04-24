CREATE INDEX IF NOT EXISTS idx_checkpoint_tx_offchain_txid
    ON checkpoint_tx (offchain_txid);

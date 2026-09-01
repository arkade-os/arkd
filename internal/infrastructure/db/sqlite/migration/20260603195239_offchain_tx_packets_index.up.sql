CREATE INDEX IF NOT EXISTS offchain_tx_with_packets_idx
    ON offchain_tx (txid)
    WHERE packets IS NOT NULL AND packets <> '';

-- The admin batch listing filters and orders by starting_timestamp. Without this
-- index every listing is a full scan of the round table.
CREATE INDEX IF NOT EXISTS idx_round_starting_timestamp ON round(starting_timestamp);

-- Offchain tx listing does the same over its own table.
CREATE INDEX IF NOT EXISTS idx_offchain_tx_starting_timestamp
    ON offchain_tx(starting_timestamp);

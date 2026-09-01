-- The backfill scans WHERE packets IS NULL AND txid > @cursor on every start.
-- offchain_tx_with_packets_idx is the complement and cannot serve it, so that
-- scan hits the heap and its cost grows with the table even after every row is
-- backfilled. This partial index covers the scan and, once the backfill is
-- done, holds no rows at all, so a restart stops paying for it entirely.
CREATE INDEX IF NOT EXISTS offchain_tx_without_packets_idx
    ON offchain_tx (txid)
    WHERE packets IS NULL;

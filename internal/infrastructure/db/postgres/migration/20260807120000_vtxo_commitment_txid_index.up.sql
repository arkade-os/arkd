-- The scheduled-sweeps aggregate sums leaf vtxos per commitment txid. The
-- existing idx_vtxo_commitment_txid_commitment_txid is on the
-- vtxo_commitment_txid join table, not on vtxo itself.
CREATE INDEX IF NOT EXISTS idx_vtxo_commitment_txid ON vtxo(commitment_txid);

CREATE INDEX IF NOT EXISTS idx_vtxo_pubkey_updated_at
    ON vtxo (pubkey, updated_at);

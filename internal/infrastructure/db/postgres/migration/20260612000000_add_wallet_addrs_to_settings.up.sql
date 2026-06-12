ALTER TABLE settings
    ADD COLUMN wallet_addr TEXT NOT NULL DEFAULT '',
    ADD COLUMN wallet_fallback_addrs TEXT NOT NULL DEFAULT '';

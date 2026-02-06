CREATE TABLE IF NOT EXISTS virtual_txs_requests (
    id INTEGER PRIMARY KEY,
    auth_code TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expiry INTEGER NOT NULL
);

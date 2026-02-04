CREATE TABLE IF NOT EXISTS virtual_txs_requests (
    id SERIAL PRIMARY KEY,
    auth_code UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    expiry BIGINT NOT NULL
);
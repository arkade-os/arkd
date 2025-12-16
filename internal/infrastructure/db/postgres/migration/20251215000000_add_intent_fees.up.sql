CREATE TABLE IF NOT EXISTS intent_fees (
    id TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    offchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    offchain_output_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_output_fee_program TEXT NOT NULL DEFAULT '0.0'
);

-- add a row with default values if not exists
INSERT INTO intent_fees (id, created_at)
VALUES ('singleton', EXTRACT(EPOCH FROM now())::bigint)
ON CONFLICT (id) DO NOTHING;
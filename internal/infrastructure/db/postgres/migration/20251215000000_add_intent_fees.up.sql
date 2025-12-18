CREATE TABLE IF NOT EXISTS intent_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
    offchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    offchain_output_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_output_fee_program TEXT NOT NULL DEFAULT '0.0'
);

-- add a row with default values if not exists
INSERT INTO intent_fees (id, created_at)
SELECT '00000000-0000-0000-0000-000000000001', EXTRACT(EPOCH FROM NOW())::BIGINT
WHERE NOT EXISTS (SELECT 1 FROM intent_fees WHERE id = '00000000-0000-0000-0000-000000000001');

-- add index on created_at for faster retrieval of latest fees
CREATE INDEX IF NOT EXISTS idx_intent_fees_created_at ON intent_fees (created_at);
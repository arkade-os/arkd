CREATE TABLE IF NOT EXISTS intent_fees (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    created_at BIGINT NOT NULL DEFAULT (CAST((strftime('%s','now') || substr(strftime('%f','now'),4,3)) AS INTEGER)),
    offchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_input_fee_program TEXT NOT NULL DEFAULT '0.0',
    offchain_output_fee_program TEXT NOT NULL DEFAULT '0.0',
    onchain_output_fee_program TEXT NOT NULL DEFAULT '0.0'
);

-- add a row with default values if not exists
INSERT INTO intent_fees (id, created_at)
SELECT 'singleton', strftime('%s','now')
WHERE NOT EXISTS (SELECT 1 FROM intent_fees WHERE id = 'singleton');

-- add index on created_at for faster retrieval of latest fees
CREATE INDEX IF NOT EXISTS idx_intent_fees_created_at ON intent_fees (created_at);
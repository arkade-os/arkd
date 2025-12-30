CREATE TABLE IF NOT EXISTS intent_fees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at BIGINT NOT NULL DEFAULT (CAST((strftime('%s','now') || substr(strftime('%f','now'),4,3)) AS INTEGER)),
    offchain_input_fee_program TEXT NOT NULL DEFAULT '',
    onchain_input_fee_program TEXT NOT NULL DEFAULT '',
    offchain_output_fee_program TEXT NOT NULL DEFAULT '',
    onchain_output_fee_program TEXT NOT NULL DEFAULT ''
);
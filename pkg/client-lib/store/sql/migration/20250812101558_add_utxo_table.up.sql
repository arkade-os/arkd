CREATE TABLE IF NOT EXISTS utxo (
	txid TEXT NOT NULL,
	vout INTEGER NOT NULL,
	script TEXT NOT NULL,
	amount INTEGER NOT NULL,
	spent_by TEXT,
	spent BOOLEAN NOT NULL,
    tapscripts TEXT,
    spendable_at INTEGER,
    created_at INTEGER,
    delay_value INTEGER,
    delay_type TEXT,
    tx TEXT,
    PRIMARY KEY (txid, vout)
);
CREATE TABLE IF NOT EXISTS vtxo (
	txid TEXT NOT NULL,
	vout INTEGER NOT NULL,
	script TEXT NOT NULL,
	amount INTEGER NOT NULL,
	commitment_txids TEXT NOT NULL,
	spent_by TEXT,
	spent BOOLEAN NOT NULL,
	expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    preconfirmed BOOLEAN NOT NULL,
    swept BOOLEAN NOT NULL,
    redeemed BOOLEAN NOT NULL,
    PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS tx (
    txid TEXT NOT NULL PRIMARY KEY,
    txid_type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    settled BOOLEAN NOT NULL,
    created_at INTEGER NOT NULL,
    hex TEXT
);

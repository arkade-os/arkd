CREATE TABLE IF NOT EXISTS round (
    id TEXT PRIMARY KEY,
    starting_timestamp INTEGER NOT NULL,
    ending_timestamp INTEGER NOT NULL,
    ended BOOLEAN NOT NULL DEFAULT FALSE,
    failed BOOLEAN NOT NULL DEFAULT FALSE,
    stage_code INTEGER NOT NULL,
    connector_address TEXT NOT NULL,
    version INTEGER NOT NULL,
    swept BOOLEAN NOT NULL DEFAULT FALSE,
    vtxo_tree_expiration INTEGER NOT NULL,
    fail_reason TEXT
);

CREATE TABLE IF NOT EXISTS intent (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL,
    proof TEXT NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS receiver (
    intent_id TEXT NOT NULL,
    pubkey TEXT,
    onchain_address TEXT,
    amount INTEGER NOT NULL,
    FOREIGN KEY (intent_id) REFERENCES intent(id),
    PRIMARY KEY (intent_id, pubkey, onchain_address)
);

CREATE TABLE IF NOT EXISTS tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL,
    round_id TEXT NOT NULL,
    type TEXT NOT NULL,
    position INTEGER NOT NULL,
    children TEXT,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS vtxo (
	txid TEXT NOT NULL,
	vout INTEGER NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
	commitment_txid TEXT NOT NULL,
	spent_by TEXT,
	spent BOOLEAN NOT NULL DEFAULT FALSE,
	unrolled BOOLEAN NOT NULL DEFAULT FALSE,
	swept BOOLEAN NOT NULL DEFAULT FALSE,
    preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
    settled_by TEXT,
    ark_txid TEXT,
	intent_id TEXT,
    PRIMARY KEY (txid, vout),
	FOREIGN KEY (intent_id) REFERENCES intent(id)
);

CREATE TABLE IF NOT EXISTS vtxo_commitment_txid (
    vtxo_txid TEXT NOT NULL,
    vtxo_vout INTEGER NOT NULL,
    commitment_txid TEXT NOT NULL,
    PRIMARY KEY (vtxo_txid, vtxo_vout, commitment_txid),
    FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxo(txid, vout)
);

CREATE TABLE IF NOT EXISTS offchain_tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL,
    starting_timestamp BIGINT NOT NULL,
    ending_timestamp BIGINT NOT NULL,
    expiry_timestamp BIGINT NOT NULL,
    fail_reason TEXT,
    stage_code INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoint_tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL,
    commitment_txid TEXT NOT NULL,
    is_root_commitment_txid BOOLEAN NOT NULL DEFAULT FALSE,
    offchain_txid TEXT NOT NULL,
    FOREIGN KEY (offchain_txid) REFERENCES offchain_tx(txid)
);

CREATE TABLE IF NOT EXISTS market_hour (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   start_time INTEGER NOT NULL,
   end_time INTEGER NOT NULL,
   period INTEGER NOT NULL,
   round_interval INTEGER NOT NULL,
   updated_at INTEGER NOT NULL
);

CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(group_concat(vc.commitment_txid), '') AS commitments
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc
ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
GROUP BY v.txid, v.vout;

CREATE VIEW round_intents_vw AS
SELECT intent.*
FROM round
LEFT OUTER JOIN intent
ON round.id=intent.round_id;

CREATE VIEW round_txs_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id=tx.round_id;

CREATE VIEW round_with_commitment_tx_vw AS
SELECT round.*, tx.*
FROM round
INNER JOIN tx
ON round.id = tx.round_id AND tx.type = 'commitment';

CREATE VIEW intent_with_receivers_vw AS
SELECT receiver.*, intent.*
FROM intent
LEFT OUTER JOIN receiver
ON intent.id=receiver.intent_id;

CREATE VIEW intent_inputs_vw AS
SELECT vtxo_vw.*, intent.*
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

CREATE VIEW offchain_tx_vw AS
SELECT
    offchain_tx.*,
    checkpoint_tx.txid AS checkpoint_txid,
    checkpoint_tx.tx AS checkpoint_tx,
    checkpoint_tx.commitment_txid,
    checkpoint_tx.is_root_commitment_txid,
    checkpoint_tx.offchain_txid
FROM offchain_tx
    INNER JOIN checkpoint_tx
    ON offchain_tx.txid = checkpoint_tx.offchain_txid;
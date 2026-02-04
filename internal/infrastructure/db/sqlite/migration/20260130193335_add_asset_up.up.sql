CREATE TABLE IF NOT EXISTS asset (
    id TEXT NOT NULL PRIMARY KEY,
    is_immutable BOOLEAN NOT NULL,
    metadata_hash TEXT,
    metadata TEXT,
    control_asset_id TEXT,
    FOREIGN KEY (control_asset_id) REFERENCES asset(id)
);

CREATE TABLE IF NOT EXISTS asset_projection (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    fk_intent_txid TEXT,
    fk_intent_vout INTEGER,
    fk_asset_id TEXT NOT NULL,
    fk_vtxo_txid TEXT,
    fk_vtxo_vout INTEGER,
    amount INTEGER NOT NULL,
    FOREIGN KEY (fk_asset_id) REFERENCES asset(id) ON DELETE CASCADE,
    FOREIGN KEY (fk_vtxo_txid, fk_vtxo_vout) REFERENCES vtxo(txid, vout) ON DELETE CASCADE,
    FOREIGN KEY (fk_intent_txid) REFERENCES intent(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_metadata_update (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fk_asset_id TEXT NOT NULL,
    fk_intent_txid TEXT,
    fk_txid TEXT,
    metadata_hash TEXT NOT NULL,
    FOREIGN KEY (fk_asset_id) REFERENCES asset(id),
    FOREIGN KEY (fk_txid) REFERENCES offchain_tx(txid),
    FOREIGN KEY (fk_intent_txid) REFERENCES intent(id)
);

DROP VIEW IF EXISTS intent_with_inputs_vw;
DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT
  v.*,
  COALESCE((
    SELECT group_concat(commitment_txid, ',')
    FROM vtxo_commitment_txid
    WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
  ), '') AS commitments,
  COALESCE(ap.fk_asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN (
  SELECT DISTINCT fk_vtxo_txid, fk_vtxo_vout, fk_asset_id, amount
  FROM asset_projection
) AS ap
ON ap.fk_vtxo_txid = v.txid AND ap.fk_vtxo_vout = v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

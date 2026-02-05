CREATE TABLE IF NOT EXISTS asset (
    id TEXT NOT NULL PRIMARY KEY,
    is_immutable BOOLEAN NOT NULL,
    metadata_hash TEXT,
    metadata JSONB,
    control_asset_id TEXT,
    FOREIGN KEY (control_asset_id) REFERENCES asset(id)
);

CREATE TABLE IF NOT EXISTS asset_projection (
    asset_id TEXT NOT NULL,
    txid TEXT NOT NULL,
    vout BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    PRIMARY KEY (asset_id, txid, vout),
    FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE CASCADE,
    FOREIGN KEY (txid, vout) REFERENCES vtxo(txid, vout) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_metadata_update (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
  COALESCE(vc.commitments, '') AS commitments,
  COALESCE(ap.asset_id, '') AS asset_id,
  COALESCE(ap.amount, 0) AS asset_amount
FROM vtxo v
LEFT JOIN LATERAL (
  SELECT string_agg(commitment_txid, ',') AS commitments
  FROM vtxo_commitment_txid
  WHERE vtxo_txid = v.txid AND vtxo_vout = v.vout
) vc ON true
LEFT JOIN (
  SELECT txid, vout, asset_id, amount
  FROM asset_projection
  GROUP BY txid, vout, asset_id, amount
) ap
ON ap.txid = v.txid AND ap.vout = v.vout;

CREATE VIEW intent_with_inputs_vw AS
SELECT vtxo_vw.*, intent.id, intent.round_id, intent.proof, intent.message, intent.txid AS intent_txid
FROM intent
LEFT OUTER JOIN vtxo_vw
ON intent.id = vtxo_vw.intent_id;

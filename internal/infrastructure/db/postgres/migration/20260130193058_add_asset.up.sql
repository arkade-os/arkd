CREATE TABLE IF NOT EXISTS asset (
    id TEXT NOT NULL PRIMARY KEY,
    is_immutable BOOLEAN NOT NULL,
    metadata_hash TEXT,
    metadata TEXT,
    control_asset_id TEXT,
    FOREIGN KEY (control_asset_id) REFERENCES asset(id)
);

CREATE TABLE IF NOT EXISTS asset_projection (
    asset_id TEXT NOT NULL,
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    amount NUMERIC(20,0) NOT NULL,
    CONSTRAINT asset_projection_pkey PRIMARY KEY (asset_id, txid, vout),
    CONSTRAINT asset_projection_asset_fkey FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE CASCADE,
    CONSTRAINT asset_projection_vtxo_fkey FOREIGN KEY (txid, vout) REFERENCES vtxo(txid, vout) ON DELETE CASCADE,
    CONSTRAINT asset_projection_amount_u64_check CHECK (amount >= 0 AND amount <= 18446744073709551615::numeric)
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

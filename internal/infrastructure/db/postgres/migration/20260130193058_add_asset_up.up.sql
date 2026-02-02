CREATE TABLE IF NOT EXISTS asset (
    genesis_txid TEXT NOT NULL,
    genesis_group_index BIGINT NOT NULL,
    is_immutable BOOLEAN NOT NULL,
    metadata_hash TEXT,
    metadata JSONB,
    control_asset_id TEXT,
    control_asset_group_index BIGINT,
    PRIMARY KEY (genesis_txid, genesis_group_index),
    FOREIGN KEY (control_asset_id, control_asset_group_index) REFERENCES asset(genesis_txid, genesis_group_index)
);

CREATE TABLE IF NOT EXISTS asset_projection (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type TEXT NOT NULL,
    fk_intent_txid TEXT,
    fk_intent_vout BIGINT,
    fk_asset_id TEXT NOT NULL,
    fk_asset_index TEXT NOT NULL,
    fk_vtxo_txid TEXT,
    fk_vtxo_vout BIGINT,
    amount BIGINT NOT NULL,
    FOREIGN KEY (fk_asset_id, fk_asset_index) REFERENCES asset(genesis_txid, genesis_group_index) ON DELETE CASCADE,
    FOREIGN KEY (fk_vtxo_txid, fk_vtxo_vout) REFERENCES vtxo(txid, vout) ON DELETE CASCADE,
    FOREIGN KEY (fk_intent_txid) REFERENCES intent(txid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_metadata_update (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fk_asset_id TEXT NOT NULL,
    fk_asset_index TEXT NOT NULL,
    fk_intent_txid TEXT,
    fk_intent_vout BIGINT,
    fk_txid TEXT,
    metadata_hash TEXT NOT NULL,
    FOREIGN KEY (fk_asset_id, fk_asset_index) REFERENCES asset(genesis_txid, genesis_group_index) ON DELETE CASCADE,
    FOREIGN KEY (fk_txid) REFERENCES offchain_tx(txid) ON DELETE CASCADE,
    FOREIGN KEY (fk_intent_txid) REFERENCES intent(txid) ON DELETE CASCADE
);

DROP VIEW IF EXISTS vtxo_vw;

CREATE VIEW vtxo_vw AS
SELECT v.*, COALESCE(string_agg(vc.commitment_txid, ','), '') AS commitments, ap.fk_asset_id, ap.fk_asset_index
FROM vtxo v
LEFT JOIN vtxo_commitment_txid vc ON v.txid = vc.vtxo_txid AND v.vout = vc.vtxo_vout
LEFT JOIN asset_projection ap ON v.txid = ap.fk_vtxo_txid AND v.vout = ap.fk_vtxo_vout
GROUP BY v.txid, v.vout, ap.fk_asset_id, ap.fk_asset_index;

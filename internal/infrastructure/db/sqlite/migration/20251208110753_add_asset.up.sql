PRAGMA foreign_keys = ON;

CREATE TABLE asset_anchors (
    anchor_txid  TEXT PRIMARY KEY,
    anchor_vout  INTEGER NOT NULL,
    asset_id    TEXT    NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE anchor_vtxos (
    anchor_id   TEXT    NOT NULL,
    vout        INTEGER NOT NULL,
    amount      INTEGER NOT NULL,
    PRIMARY KEY (anchor_id, vout),
    FOREIGN KEY (anchor_id) REFERENCES asset_anchors(anchor_txid) ON DELETE CASCADE
);

CREATE TABLE asset_metadata (
    asset_id   TEXT    NOT NULL,
    meta_key    TEXT    NOT NULL,
    meta_value  TEXT    NOT NULL,
    PRIMARY KEY (asset_id, meta_key),
    FOREIGN KEY (asset_id) REFERENCES asset_anchors(id) ON DELETE CASCADE
);

CREATE TABLE assets (
    id           TEXT PRIMARY KEY,
    immutable    BOOLEAN NOT NULL DEFAULT 0,
    quantity     INTEGER NOT NULL
);

CREATE TABLE teleport_assets (
    teleport_hash         TEXT PRIMARY KEY,
    asset_id     TEXT    NOT NULL,
    amount       INTEGER NOT NULL,
    is_claimed   BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);



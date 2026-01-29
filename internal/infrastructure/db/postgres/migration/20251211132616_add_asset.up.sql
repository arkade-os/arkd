CREATE TABLE asset_group (
    id        TEXT PRIMARY KEY,
    immutable BOOLEAN NOT NULL DEFAULT FALSE,
    quantity  BIGINT NOT NULL,
    control_id TEXT 
);

CREATE TABLE asset_anchor (
    anchor_txid  TEXT PRIMARY KEY,
    anchor_vout  BIGINT NOT NULL
);

CREATE TABLE asset (
    anchor_id  TEXT NOT NULL,
    asset_id   TEXT NOT NULL,
    vout       BIGINT NOT NULL,
    amount     BIGINT NOT NULL,
    PRIMARY KEY (anchor_id, vout),
    FOREIGN KEY (anchor_id)
        REFERENCES asset_anchor(anchor_txid)
        ON DELETE CASCADE,
    FOREIGN KEY (asset_id)
        REFERENCES asset_group(id)
        ON DELETE CASCADE
);

CREATE TABLE asset_metadata (
    asset_id    TEXT NOT NULL,
    meta_key    TEXT NOT NULL,
    meta_value  TEXT NOT NULL,
    PRIMARY KEY (asset_id, meta_key),
    FOREIGN KEY (asset_id)
        REFERENCES asset_group(id)
        ON DELETE CASCADE
);

CREATE TABLE teleport_asset (
    script         TEXT NOT NULL,
    intent_id      TEXT NOT NULL,
    group_index           BIGINT NOT NULL,
    asset_id     TEXT    NOT NULL,
    amount        BIGINT NOT NULL,
    is_claimed    BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (script, intent_id, asset_id, group_index),
    FOREIGN KEY (asset_id)
        REFERENCES asset_group(id)
        ON DELETE CASCADE
);

CREATE TABLE onchain_tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL
);

CREATE TABLE utxo (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    -- NULL ⇒ the outpoint is an unrolled vtxo, attributes come from vtxo
    pubkey TEXT,
    amount BIGINT,
    spent_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    spend_confirmed_at_time BIGINT,
    spend_confirmed_at_height BIGINT,
    PRIMARY KEY (txid, vout),
    CHECK ((pubkey IS NULL) = (amount IS NULL))   -- all-or-nothing
);

CREATE VIEW utxo_vw AS
SELECT
    u.txid, u.vout,
    COALESCE(u.pubkey, v.pubkey) AS pubkey,
    COALESCE(u.amount, v.amount) AS amount,
    u.spent_by, u.created_at,
    u.spend_confirmed_at_time, u.spend_confirmed_at_height,
    (v.txid IS NOT NULL) AS is_vtxo
FROM utxo u
LEFT JOIN vtxo v ON v.txid = u.txid AND v.vout = u.vout;

CREATE FUNCTION check_utxo_shape() RETURNS trigger AS $$
DECLARE is_unrolled_vtxo BOOLEAN;
BEGIN
    SELECT unrolled INTO is_unrolled_vtxo FROM vtxo WHERE txid = NEW.txid AND vout = NEW.vout;
    IF NEW.pubkey IS NULL AND NOT COALESCE(is_unrolled_vtxo, false) THEN
        RAISE EXCEPTION 'utxo %:% has no attributes and is not an unrolled vtxo', NEW.txid, NEW.vout;
    END IF;
    IF NEW.pubkey IS NOT NULL AND is_unrolled_vtxo IS NOT NULL THEN
        RAISE EXCEPTION 'utxo %:% duplicates a vtxo', NEW.txid, NEW.vout;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER utxo_shape BEFORE INSERT ON utxo
FOR EACH ROW EXECUTE FUNCTION check_utxo_shape();
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

  CREATE TRIGGER utxo_pointer_must_be_unrolled_vtxo BEFORE INSERT ON utxo
  WHEN NEW.pubkey IS NULL AND NOT EXISTS (
      SELECT 1 FROM vtxo WHERE txid = NEW.txid AND vout = NEW.vout AND unrolled = true
  ) BEGIN SELECT RAISE(ABORT, 'utxo has no attributes and is not an unrolled vtxo'); END;

  CREATE TRIGGER utxo_must_not_duplicate_vtxo BEFORE INSERT ON utxo
  WHEN NEW.pubkey IS NOT NULL AND EXISTS (
      SELECT 1 FROM vtxo WHERE txid = NEW.txid AND vout = NEW.vout
  ) BEGIN SELECT RAISE(ABORT, 'utxo duplicates a vtxo'); END;
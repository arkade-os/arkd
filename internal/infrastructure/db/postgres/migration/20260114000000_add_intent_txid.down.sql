DROP INDEX IF EXISTS idx_intent_txid;
ALTER TABLE intent DROP COLUMN txid;

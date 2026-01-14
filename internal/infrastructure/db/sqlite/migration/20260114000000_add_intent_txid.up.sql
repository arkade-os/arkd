-- update intent table to have a new column txid, make int unique and and not null
ALTER TABLE intent
ADD COLUMN txid TEXT;

-- create an index on the new txid column for faster lookups
CREATE INDEX IF NOT EXISTS idx_intent_txid ON intent(txid);

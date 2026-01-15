-- update intent table to have a new column txid, make int unique and and not null
ALTER TABLE intent
ADD COLUMN txid TEXT;

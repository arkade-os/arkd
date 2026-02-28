ALTER TABLE round ADD COLUMN collected_fees BIGINT NOT NULL DEFAULT 0 CHECK (collected_fees >= 0);

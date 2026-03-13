-- SQLite doesn't support DROP COLUMN easily, but this is a best-effort down migration.
-- For SQLite < 3.35.0, this would need table recreation.
ALTER TABLE marker DROP COLUMN created_at;

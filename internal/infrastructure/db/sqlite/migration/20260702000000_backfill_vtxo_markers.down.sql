-- Irreversible: the backfill rebuilds the marker DAG in place. Down is a no-op;
-- roll back by restoring a pre-migration backup.
SELECT 1;

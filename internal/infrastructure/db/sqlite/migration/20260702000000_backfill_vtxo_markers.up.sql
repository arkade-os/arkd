-- Sentinel for the vtxo-marker DAG backfill. No schema changes: marker,
-- swept_marker, and swept_vtxo already exist (20260701000000 / 20260701000001).
-- The data work is done by sqlitedb.BackfillVtxoMarkers, invoked from
-- handleVtxoMarkersMigration after migrating up to this version.
SELECT 1;

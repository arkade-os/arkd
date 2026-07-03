-- Sentinel for the vtxo-marker DAG backfill. No schema changes: the marker,
-- swept_marker, and swept_vtxo tables already exist (20260701000000 /
-- 20260701000001). The data work is done by pgdb.BackfillVtxoMarkers, invoked
-- from handleVtxoMarkersMigration after migrating up to this version.
SELECT 1;

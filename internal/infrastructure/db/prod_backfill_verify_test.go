package db_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	postgresdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// TestProdBackfillCreatesTopology runs the marker-DAG Go backfill against a scratch
// DB restored from prod and already schema-migrated (self-markers, depth 0). It proves
// pre-existing prod vtxos get real BFS depths + boundary markers (the preloadByMarkers
// fast path), with swept status preserved and the run idempotent.
//
//	PROD_SCRATCH_DSN='postgresql://postgres:demo@127.0.0.1:5434/projection_verify?sslmode=disable' \
//	  go test ./internal/infrastructure/db/ -run TestProdBackfillCreatesTopology -v
func TestProdBackfillCreatesTopology(t *testing.T) {
	dsn := os.Getenv("PROD_SCRATCH_DSN")
	if dsn == "" {
		t.Skip("set PROD_SCRATCH_DSN (scratch postgres restored from a prod dump, already migrated)")
	}

	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, db.Ping())

	var hasMarkers bool
	require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.columns
		WHERE table_name='vtxo' AND column_name='markers')`).Scan(&hasMarkers))
	if !hasMarkers {
		t.Skip("DAG schema not present; run the migrations first")
	}

	scalar := func(q string) int64 {
		var n int64
		require.NoError(t, db.QueryRow(q).Scan(&n))
		return n
	}
	countMarkers := func() int64 { return scalar(`SELECT count(*) FROM marker`) }
	countBoundary := func() int64 {
		return scalar(`SELECT count(*) FROM marker
			WHERE parent_markers IS NOT NULL AND parent_markers <> '[]'::jsonb
			  AND id <> '__vtxo_markers_backfill_done__'`)
	}
	maxDepth := func() int64 { return scalar(`SELECT COALESCE(max(depth),0) FROM vtxo`) }
	inChains := func() int64 { return scalar(`SELECT count(*) FROM vtxo WHERE depth > 0`) }
	swept := func() int64 { return scalar(`SELECT count(*) FROM vtxo_vw WHERE swept = true`) }
	latch := func() bool {
		var ok bool
		require.NoError(t, db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM marker WHERE id='__vtxo_markers_backfill_done__')`).Scan(&ok))
		return ok
	}

	vtxos := scalar(`SELECT count(*) FROM vtxo`)
	sweptBefore := swept()
	t.Logf("BEFORE: vtxos=%d markers=%d boundary=%d maxDepth=%d inChains=%d swept=%d latch=%v",
		vtxos, countMarkers(), countBoundary(), maxDepth(), inChains(), sweptBefore, latch())

	start := time.Now()
	require.NoError(t, postgresdb.BackfillVtxoMarkers(context.Background(), db))
	dur := time.Since(start)

	boundaryAfter, depthAfter, chainsAfter, sweptAfter := countBoundary(), maxDepth(), inChains(), swept()
	t.Logf("AFTER : markers=%d boundary=%d maxDepth=%d inChains=%d swept=%d latch=%v (%.1fs on %d vtxos)",
		countMarkers(), boundaryAfter, depthAfter, chainsAfter, sweptAfter, latch(), dur.Seconds(), vtxos)

	require.Greater(t, boundaryAfter, int64(0), "backfill must create boundary markers (real DAG topology)")
	require.Greater(t, depthAfter, int64(0), "backfill must compute real BFS depths for existing chains")
	require.Equal(t, sweptBefore, sweptAfter, "swept status must be preserved across the backfill")
	require.True(t, latch(), "completion latch must be written")

	// Idempotency: a second run trips the latch guard and changes nothing.
	require.NoError(t, postgresdb.BackfillVtxoMarkers(context.Background(), db))
	require.Equal(t, boundaryAfter, countBoundary(), "re-run must be a no-op (idempotent)")
	require.Equal(t, sweptAfter, swept(), "re-run must not change swept")
	t.Logf("re-run idempotent: boundary=%d swept=%d", countBoundary(), swept())
}

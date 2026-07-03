package db_test

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/require"
)

//go:embed sqlite/migration/*
var demoBackfillMigrations embed.FS

// TestBackfillEnablesBulkPreload_Demo proves, against a real sqlite DB, that the
// marker-DAG backfill promotes "legacy" vtxos (self-markers, depth 0 — exactly
// what 20260701000000_add_vtxo_marker_dag leaves for pre-existing rows) onto
// the preloadByMarkers fast path.
//
// It seeds a deep linear preconfirmed chain in the legacy shape, then measures
// how many bulk marker-window loads (the GetVtxoChainByMarkers path) are needed
// to cover the whole chain BEFORE vs AFTER BackfillVtxoMarkers. Run it with:
//
//	go test ./internal/infrastructure/db/ -run TestBackfillEnablesBulkPreload_Demo -v
func TestBackfillEnablesBulkPreload_Demo(t *testing.T) {
	const chainLen = 300
	ctx := context.Background()

	sdb, err := sqlitedb.OpenDb(filepath.Join(t.TempDir(), "demo.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sdb.Write().Close() })
	db := sdb.Write()

	// Apply all migrations for schema only. The Go backfill is NOT run here
	// (it is invoked by handleVtxoMarkersMigration, which we bypass), so we get
	// full control over the before/after.
	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	require.NoError(t, err)
	src, err := iofs.New(demoBackfillMigrations, "sqlite/migration")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, "arkdb", driver)
	require.NoError(t, err)
	require.NoError(t, m.Up())

	// Seed a linear preconfirmed chain in the LEGACY shape: every vtxo sits at
	// depth 0 with its own self-marker (id = outpoint) and no parent topology.
	txAt := func(i int) string { return fmt.Sprintf("%064x", i+1) }
	self := func(i int) string { return txAt(i) + ":0" }
	seedTx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	for i := 0; i < chainLen; i++ {
		// ark_txid links a vtxo to the tx that SPENT it (its child), so the
		// deepest vtxo (the unspent tip) has a NULL ark_txid.
		var ark any
		if i < chainLen-1 {
			ark = txAt(i + 1)
		}
		_, err := seedTx.ExecContext(ctx, `
			INSERT INTO vtxo (txid, vout, pubkey, amount, expires_at, created_at,
			                  commitment_txid, preconfirmed, ark_txid, depth, markers)
			VALUES (?, 0, 'pk', 1000, 9999999999, 0, '', 1, ?, 0, ?)`,
			txAt(i), ark, `["`+self(i)+`"]`)
		require.NoError(t, err)
		_, err = seedTx.ExecContext(ctx,
			`INSERT INTO marker (id, depth, parent_markers) VALUES (?, 0, '[]')`, self(i))
		require.NoError(t, err)
	}
	require.NoError(t, seedTx.Commit())

	// --- measurement helpers (mirror the GetVtxoChainByMarkers window load) ---
	windowSize := func(markerID string) int {
		var n int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT count(*) FROM vtxo_vw WHERE markers LIKE '%"' || ? || '"%'`,
			markerID).Scan(&n))
		return n
	}
	splitJSON := func(s string) []string {
		s = strings.Trim(s, "[]")
		if s == "" {
			return nil
		}
		var out []string
		for _, p := range strings.Split(s, ",") {
			out = append(out, strings.Trim(p, `" `))
		}
		return out
	}
	parentsOf := func(markerID string) []string {
		var pm sql.NullString
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT parent_markers FROM marker WHERE id = ?`, markerID).Scan(&pm))
		if !pm.Valid {
			return nil
		}
		return splitJSON(pm.String)
	}
	tipMarkers := func() []string {
		var mk string
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT markers FROM vtxo WHERE txid = ?`, txAt(chainLen-1)).Scan(&mk))
		return splitJSON(mk)
	}
	// Walk the marker DAG upward from the tip, as preloadByMarkers does: each
	// distinct marker is one bulk GetVtxoChainByMarkers call that returns its
	// whole window. Returns (bulk calls, distinct vtxos those windows cover).
	walk := func() (calls, covered int) {
		seenM := map[string]bool{}
		frontier := tipMarkers()
		for len(frontier) > 0 {
			var next []string
			for _, mk := range frontier {
				if seenM[mk] {
					continue
				}
				seenM[mk] = true
				calls++
				covered += windowSize(mk)
				next = append(next, parentsOf(mk)...)
			}
			frontier = next
		}
		return calls, covered
	}
	countTopology := func() int {
		var n int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT count(*) FROM marker WHERE parent_markers IS NOT NULL AND parent_markers <> '[]'`).Scan(&n))
		return n
	}

	// --- BEFORE ---
	topoBefore := countTopology()
	callsBefore, coveredBefore := walk()

	// --- BACKFILL (the migration data step) ---
	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, db))

	// --- AFTER ---
	topoAfter := countTopology()
	callsAfter, coveredAfter := walk()
	var maxDepth int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT max(depth) FROM vtxo`).Scan(&maxDepth))

	t.Logf("\n============= marker-DAG backfill demo (linear chain of %d vtxos) =============", chainLen)
	t.Logf("BEFORE: marker DAG is flat — %d markers carry topology; walking from the tip",
		topoBefore)
	t.Logf("        covers %d/%d vtxos in %d marker-window load(s). The other %d vtxos share",
		coveredBefore, chainLen, callsBefore, chainLen-coveredBefore)
	t.Logf("        no marker, so GetVtxoChain reads them one-by-one -> ~%d DB reads.", chainLen)
	t.Logf("AFTER : %d boundary markers now carry topology (max depth=%d); walking from the tip",
		topoAfter, maxDepth)
	t.Logf("        covers %d/%d vtxos in %d bulk marker-window load(s) of ~%d vtxos each",
		coveredAfter, chainLen, callsAfter, chainLen/max1(callsAfter))
	t.Logf("        -> %d DB reads.", callsAfter)
	t.Logf("RESULT: chain load drops from ~%d per-VTXO reads to %d bulk reads (~%dx fewer round-trips).",
		chainLen, callsAfter, chainLen/max1(callsAfter))
	t.Logf("===============================================================================")

	// Assertions proving the mechanism, not just printing numbers.
	require.Equal(t, 0, topoBefore, "legacy state must have no marker topology")
	require.Equal(t, 1, coveredBefore,
		"before backfill, the tip's self-marker window covers only itself")
	require.Equal(t, chainLen-1, maxDepth, "backfill must compute real BFS depths")
	require.Greater(t, topoAfter, 0, "backfill must create boundary markers with parent links")
	require.Equal(t, chainLen, coveredAfter,
		"after backfill, the whole chain is covered by marker windows")
	require.LessOrEqual(t, callsAfter, chainLen/100+2,
		"after backfill, the chain loads in ~N/100 bulk marker-window calls")
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

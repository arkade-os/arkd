package sqlitedb_test

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/require"
)

//go:embed migration/*
var vtxoMarkerTestMigrations embed.FS

// baseline schema version that establishes vtxo, marker, swept_marker,
// swept_vtxo, and vtxo_vw. The backfill runs against this legacy shape.
const vtxoMarkerBaselineVersion = 20260701000000

// newMarkerMigratedDB returns a fresh in-memory sqlite DB migrated to the
// swept_vtxo baseline via the real embedded migration source.
func newMarkerMigratedDB(t *testing.T) sqlitedb.SQLiteDB {
	t.Helper()
	db, err := sqlitedb.OpenDb("file::memory:", sqlitedb.WithSharedCache())
	require.NoError(t, err)
	t.Cleanup(func() {
		//nolint:errcheck
		db.Close()
	})

	driver, err := sqlitemigrate.WithInstance(db.Write(), &sqlitemigrate.Config{})
	require.NoError(t, err)
	source, err := iofs.New(vtxoMarkerTestMigrations, "migration")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(vtxoMarkerBaselineVersion))
	return db
}

// insertLegacyVtxo inserts a vtxo carrying only a legacy self-marker (bare
// "txid:vout" at the given depth, parent_markers='[]'), mirroring the state the
// 20260701000000 migration leaves. If swept is true, its self-marker is copied
// into swept_marker so the pre-backfill vtxo_vw.swept is true.
func insertLegacyVtxo(t *testing.T, db *sql.DB, txid string, vout int, arkTxid string, swept bool) {
	t.Helper()
	op := fmt.Sprintf("%s:%d", txid, vout)
	_, err := db.Exec(`INSERT OR IGNORE INTO marker (id, depth, parent_markers) VALUES (?, 0, '[]')`, op)
	require.NoError(t, err)

	var ark any
	if arkTxid != "" {
		ark = arkTxid
	}
	_, err = db.Exec(`
		INSERT INTO vtxo (
			txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
			spent, unrolled, preconfirmed, ark_txid, depth, markers
		) VALUES (?, ?, 'pk', 1000, 0, 0, 'commit', 0, 0, 0, ?, 0, ?)`,
		txid, vout, ark, fmt.Sprintf(`["%s"]`, op),
	)
	require.NoError(t, err)

	if swept {
		_, err = db.Exec(
			`INSERT OR IGNORE INTO swept_marker (marker_id, swept_at) VALUES (?, ?)`,
			op, 111,
		)
		require.NoError(t, err)
	}
}

// chainTxid returns a deterministic txid for a chain fixture.
func chainTxid(prefix string, k int) string { return fmt.Sprintf("%s%04d", prefix, k) }

// seedFixtures builds the fixture set described in the spec and returns the
// main-chain txids (index == depth).
func seedFixtures(t *testing.T, w *sql.DB) []string {
	t.Helper()

	// Main chain: main0000(root) -> main0001 -> ... -> main0205. A parent
	// points to its child via ark_txid, so main_k.ark_txid = main_{k+1}.
	const n = 205
	main := make([]string, n+1)
	for k := 0; k <= n; k++ {
		main[k] = chainTxid("main", k)
	}
	for k := 0; k <= n; k++ {
		ark := ""
		if k < n {
			ark = main[k+1]
		}
		insertLegacyVtxo(t, w, main[k], 0, ark, false)
	}

	// Swept chain: swp0 -> swp1 -> swp2, all swept-by-marker.
	swp := []string{"swp0", "swp1", "swp2"}
	for i, txid := range swp {
		ark := ""
		if i < len(swp)-1 {
			ark = swp[i+1]
		}
		insertLegacyVtxo(t, w, txid, 0, ark, true)
	}

	// Unswept chain: uns0 -> uns1 (no swept_marker rows).
	uns := []string{"uns0", "uns1"}
	for i, txid := range uns {
		ark := ""
		if i < len(uns)-1 {
			ark = uns[i+1]
		}
		insertLegacyVtxo(t, w, txid, 0, ark, false)
	}

	// swept_vtxo-only outpoint (checkpoint-sweep path): a vtxo not swept by
	// marker, seeded directly into swept_vtxo.
	insertLegacyVtxo(t, w, "ckpt0", 0, "", false)
	_, err := w.Exec(
		`INSERT INTO swept_vtxo (txid, vout, swept_at) VALUES ('ckpt0', 0, 999)`,
	)
	require.NoError(t, err)

	// Orphan: ark_txid points at a txid not present in the table.
	insertLegacyVtxo(t, w, "orph0", 0, "prunedparent", false)

	return main
}

func markersOf(t *testing.T, r *sql.DB, txid string, vout int) []string {
	t.Helper()
	rows, err := r.Query(
		`SELECT j.value FROM vtxo v JOIN json_each(v.markers) j
		 WHERE v.txid = ? AND v.vout = ?`, txid, vout,
	)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func depthOf(t *testing.T, r *sql.DB, txid string, vout int) int {
	t.Helper()
	var d int
	require.NoError(t, r.QueryRow(
		`SELECT depth FROM vtxo WHERE txid = ? AND vout = ?`, txid, vout,
	).Scan(&d))
	return d
}

func sweptOf(t *testing.T, r *sql.DB, txid string, vout int) bool {
	t.Helper()
	var s int
	require.NoError(t, r.QueryRow(
		`SELECT swept FROM vtxo_vw WHERE txid = ? AND vout = ?`, txid, vout,
	).Scan(&s))
	return s == 1
}

func countSwept(t *testing.T, r *sql.DB) int {
	t.Helper()
	var c int
	require.NoError(t, r.QueryRow(`SELECT COUNT(*) FROM vtxo_vw WHERE swept = 1`).Scan(&c))
	return c
}

func markerExists(t *testing.T, r *sql.DB, id string) bool {
	t.Helper()
	var c int
	require.NoError(t, r.QueryRow(`SELECT COUNT(*) FROM marker WHERE id = ?`, id).Scan(&c))
	return c > 0
}

func TestVtxoMarkerMigration_Topology(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	main := seedFixtures(t, w)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	// (a) BFS depths across the main chain.
	for k := range main {
		require.Equal(t, k, depthOf(t, r, main[k], 0), "depth at %d", k)
	}

	// boundary markers at 0/100/200 with correct parent linkage.
	rootOp := main[0] + ":0"
	m100 := fmt.Sprintf("%s:marker:100", main[100])
	m200 := fmt.Sprintf("%s:marker:200", main[200])
	require.True(t, markerExists(t, r, rootOp))
	require.True(t, markerExists(t, r, m100))
	require.True(t, markerExists(t, r, m200))

	parentMarkersOf := func(id string) string {
		var pm string
		require.NoError(t, r.QueryRow(`SELECT parent_markers FROM marker WHERE id = ?`, id).Scan(&pm))
		return pm
	}
	require.Equal(t, "[]", parentMarkersOf(rootOp))
	require.Equal(t, fmt.Sprintf(`["%s"]`, rootOp), parentMarkersOf(m100))
	require.Equal(t, fmt.Sprintf(`["%s"]`, m100), parentMarkersOf(m200))

	// inheritance.
	require.Equal(t, []string{rootOp}, markersOf(t, r, main[47], 0))
	require.Equal(t, []string{m100}, markersOf(t, r, main[150], 0))

	// latch marker present.
	require.True(t, markerExists(t, r, "__vtxo_markers_backfill_done__"))

	// orphan stays at depth 0 with a valid (non-dangling) self-marker.
	require.Equal(t, 0, depthOf(t, r, "orph0", 0))
	orphMarkers := markersOf(t, r, "orph0", 0)
	require.NotEmpty(t, orphMarkers)
	for _, id := range orphMarkers {
		require.True(t, markerExists(t, r, id), "orphan marker %s must exist", id)
	}
}

func TestVtxoMarkerMigration_SweptPreserved(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	seedFixtures(t, w)

	// pre-backfill swept expectations.
	require.True(t, sweptOf(t, r, "swp0", 0))
	require.True(t, sweptOf(t, r, "swp1", 0))
	require.True(t, sweptOf(t, r, "swp2", 0))
	require.False(t, sweptOf(t, r, "uns0", 0))
	require.True(t, sweptOf(t, r, "ckpt0", 0))
	before := countSwept(t, r)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	// post-backfill swept preserved exactly.
	require.True(t, sweptOf(t, r, "swp0", 0))
	require.True(t, sweptOf(t, r, "swp1", 0))
	require.True(t, sweptOf(t, r, "swp2", 0))
	require.False(t, sweptOf(t, r, "uns0", 0))
	require.False(t, sweptOf(t, r, "uns1", 0))
	require.True(t, sweptOf(t, r, "ckpt0", 0))
	require.Equal(t, before, countSwept(t, r))

	// swept_marker cleared; swept_vtxo carries the swept set.
	var smCount int
	require.NoError(t, r.QueryRow(`SELECT COUNT(*) FROM swept_marker`).Scan(&smCount))
	require.Equal(t, 0, smCount)

	sv := map[string]bool{}
	rows, err := r.Query(`SELECT txid FROM swept_vtxo`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var txid string
		require.NoError(t, rows.Scan(&txid))
		sv[txid] = true
	}
	require.NoError(t, rows.Err())
	require.True(t, sv["swp0"] && sv["swp1"] && sv["swp2"])
	require.True(t, sv["ckpt0"])
	require.False(t, sv["uns0"])
}

// recoverableLiquidity / expiringLiquidity run the exact SQL used by
// GetRecoverableLiquidity / GetExpiringLiquidity (both now read vtxo_vw.swept)
// so the regression test below fails if either query stops consulting
// swept_vtxo after the backfill empties swept_marker.
func recoverableLiquidity(t *testing.T, r *sql.DB) int64 {
	t.Helper()
	var amount int64
	require.NoError(t, r.QueryRow(`
		SELECT COALESCE(SUM(v.amount), 0) AS amount
		FROM vtxo_vw v
		WHERE v.swept = true
		  AND v.spent = false`).Scan(&amount))
	return amount
}

func expiringLiquidity(t *testing.T, r *sql.DB, after, before int64) int64 {
	t.Helper()
	var amount int64
	require.NoError(t, r.QueryRow(`
		SELECT COALESCE(SUM(v.amount), 0) AS amount
		FROM vtxo_vw v
		WHERE v.swept = false
		  AND v.spent = false
		  AND v.unrolled = false
		  AND v.expires_at > ?1
		  AND (?2 <= 0 OR v.expires_at < ?2)`, after, before).Scan(&amount))
	return amount
}

// TestVtxoMarkerMigration_LiquidityUnchanged pins the admin liquidity accounting
// across the backfill: swept-by-marker vtxos must stay recoverable (not flip to
// expiring) once swept_marker is emptied and their swept state lives only in
// swept_vtxo.
func TestVtxoMarkerMigration_LiquidityUnchanged(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	seedFixtures(t, w)

	// expires_at is 0 for all fixtures; after=-1/before=0 selects every
	// live (unswept, unspent, unrolled) vtxo.
	const after, before = int64(-1), int64(0)

	recoverableBefore := recoverableLiquidity(t, r)
	expiringBefore := expiringLiquidity(t, r, after, before)
	// swp0/swp1/swp2 (1000 each) + ckpt0 (1000) are swept and unspent.
	require.Equal(t, int64(4000), recoverableBefore)
	require.Positive(t, expiringBefore)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	require.Equal(t, recoverableBefore, recoverableLiquidity(t, r))
	require.Equal(t, expiringBefore, expiringLiquidity(t, r, after, before))
}

func TestVtxoMarkerMigration_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	seedFixtures(t, w)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	snap := func() (string, string, string, string) {
		return dumpTable(t, r, `SELECT id, depth, parent_markers FROM marker ORDER BY id`),
			dumpTable(t, r, `SELECT txid, vout, depth, markers FROM vtxo ORDER BY txid, vout`),
			dumpTable(t, r, `SELECT marker_id FROM swept_marker ORDER BY marker_id`),
			dumpTable(t, r, `SELECT txid, vout FROM swept_vtxo ORDER BY txid, vout`)
	}
	m1, v1, sm1, sv1 := snap()

	// second run must be a no-op (guard skip).
	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	m2, v2, sm2, sv2 := snap()

	require.Equal(t, m1, m2)
	require.Equal(t, v1, v2)
	require.Equal(t, sm1, sm2)
	require.Equal(t, sv1, sv2)
}

func TestVtxoMarkerMigration_DataGuardTripwire(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	seedFixtures(t, w)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	// insert a fresh legacy-shaped vtxo (bare self-marker) as a tripwire.
	insertLegacyVtxo(t, w, "trip0", 0, "", false)
	require.Equal(t, []string{"trip0:0"}, markersOf(t, r, "trip0", 0))
	require.Equal(t, 0, depthOf(t, r, "trip0", 0))

	// guard sees existing boundary/latch markers -> skip, tripwire untouched.
	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	require.Equal(t, []string{"trip0:0"}, markersOf(t, r, "trip0", 0))
}

func TestVtxoMarkerMigration_EmptyDB(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	// only the latch marker exists; no error.
	var total, latch int
	require.NoError(t, r.QueryRow(`SELECT COUNT(*) FROM marker`).Scan(&total))
	require.NoError(t, r.QueryRow(
		`SELECT COUNT(*) FROM marker WHERE id = '__vtxo_markers_backfill_done__'`,
	).Scan(&latch))
	require.Equal(t, 1, latch)
	require.Equal(t, 1, total)
}

func TestVtxoMarkerMigration_ShallowDAG(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()

	// chain of depth 2 (< 100): zero boundary markers, only self-markers.
	sh := []string{"sh0", "sh1", "sh2"}
	for i, txid := range sh {
		ark := ""
		if i < len(sh)-1 {
			ark = sh[i+1]
		}
		insertLegacyVtxo(t, w, txid, 0, ark, false)
	}

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	require.True(t, markerExists(t, r, "__vtxo_markers_backfill_done__"))

	// snapshot then re-run: latch must make it a no-op even with no boundary markers.
	snap := dumpTable(t, r, `SELECT txid, vout, depth, markers FROM vtxo ORDER BY txid, vout`)
	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	require.Equal(t, snap, dumpTable(t, r, `SELECT txid, vout, depth, markers FROM vtxo ORDER BY txid, vout`))
}

// TestVtxoMarkerMigration_SweptCountVerify exercises the before==after verify
// on a marker shared across two independent vtxos. Both must remain swept after
// the rebuild (each carried into swept_vtxo by its own outpoint), proving the
// copy is per-outpoint and the count is preserved rather than collapsed onto the
// shared marker.
func TestVtxoMarkerMigration_SweptCountVerify(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()

	// two distinct outpoints sharing one swept marker "shared:0".
	_, err := w.Exec(`INSERT INTO marker (id, depth, parent_markers) VALUES ('shared:0', 0, '[]')`)
	require.NoError(t, err)
	_, err = w.Exec(`INSERT INTO swept_marker (marker_id, swept_at) VALUES ('shared:0', 5)`)
	require.NoError(t, err)
	for _, txid := range []string{"sha", "shb"} {
		_, err = w.Exec(`
			INSERT INTO vtxo (txid, vout, pubkey, amount, expires_at, created_at,
				commitment_txid, spent, unrolled, preconfirmed, ark_txid, depth, markers)
			VALUES (?, 0, 'pk', 1, 0, 0, 'c', 0, 0, 0, NULL, 0, '["shared:0"]')`, txid)
		require.NoError(t, err)
	}

	before := countSwept(t, r)
	require.Equal(t, 2, before)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))

	require.Equal(t, before, countSwept(t, r))
	require.True(t, sweptOf(t, r, "sha", 0))
	require.True(t, sweptOf(t, r, "shb", 0))

	// both outpoints landed in swept_vtxo independently.
	var svc int
	require.NoError(t, r.QueryRow(
		`SELECT COUNT(*) FROM swept_vtxo WHERE txid IN ('sha','shb')`,
	).Scan(&svc))
	require.Equal(t, 2, svc)
}

func TestVtxoMarkerMigration_Wiring(t *testing.T) {
	// Drives BackfillVtxoMarkers through a fresh migrated DB twice and asserts
	// the second call is a cheap no-op via the data guard.
	ctx := context.Background()
	db := newMarkerMigratedDB(t)
	w, r := db.Write(), db.Read()
	seedFixtures(t, w)

	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	require.True(t, markerExists(t, r, "__vtxo_markers_backfill_done__"))

	first := dumpTable(t, r, `SELECT id, depth, parent_markers FROM marker ORDER BY id`)
	require.NoError(t, sqlitedb.BackfillVtxoMarkers(ctx, w))
	require.Equal(t, first, dumpTable(t, r, `SELECT id, depth, parent_markers FROM marker ORDER BY id`))
}

// dumpTable serializes a query's rows into a stable string for equality checks.
func dumpTable(t *testing.T, r *sql.DB, query string) string {
	t.Helper()
	rows, err := r.Query(query)
	require.NoError(t, err)
	defer rows.Close()
	cols, err := rows.Columns()
	require.NoError(t, err)

	var out string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		require.NoError(t, rows.Scan(ptrs...))
		for _, v := range vals {
			out += fmt.Sprintf("%v|", v)
		}
		out += "\n"
	}
	require.NoError(t, rows.Err())
	return out
}

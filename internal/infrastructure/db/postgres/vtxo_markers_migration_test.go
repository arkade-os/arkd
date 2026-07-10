package pgdb_test

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"testing"

	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

//go:embed migration/*
var vtxoMarkerPgMigrations embed.FS

const (
	vtxoMarkerPgDSN          = "postgres://root:secret@localhost:5432/event?sslmode=disable"
	vtxoMarkerPgBaseVersion  = 20260701000000
	vtxoMarkerBackfillDoneID = "__vtxo_markers_backfill_done__"
)

func TestVtxoMarkerMigration_Topology(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)
	main := pgSeedFixtures(t, db)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	for k := range main {
		require.Equal(t, k, pgDepthOf(t, db, main[k], 0), "depth at %d", k)
	}

	rootOp := main[0] + ":0"
	m100 := fmt.Sprintf("%s:marker:100", main[100])
	m200 := fmt.Sprintf("%s:marker:200", main[200])
	require.True(t, pgMarkerExists(t, db, rootOp))
	require.True(t, pgMarkerExists(t, db, m100))
	require.True(t, pgMarkerExists(t, db, m200))

	parentMarkersOf := func(id string) []string {
		rows, err := db.Query(
			`SELECT j.value FROM marker m, jsonb_array_elements_text(m.parent_markers) j
			 WHERE m.id = $1`, id,
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
	require.Empty(t, parentMarkersOf(rootOp))
	require.Equal(t, []string{rootOp}, parentMarkersOf(m100))
	require.Equal(t, []string{m100}, parentMarkersOf(m200))

	require.Equal(t, []string{rootOp}, pgMarkersOf(t, db, main[47], 0))
	require.Equal(t, []string{m100}, pgMarkersOf(t, db, main[150], 0))

	require.True(t, pgMarkerExists(t, db, vtxoMarkerBackfillDoneID))

	require.Equal(t, 0, pgDepthOf(t, db, "orph0", 0))
	orphMarkers := pgMarkersOf(t, db, "orph0", 0)
	require.NotEmpty(t, orphMarkers)
	for _, id := range orphMarkers {
		require.True(t, pgMarkerExists(t, db, id), "orphan marker %s must exist", id)
	}
}

func TestVtxoMarkerMigration_SweptPreserved(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)
	pgSeedFixtures(t, db)

	require.True(t, pgSweptOf(t, db, "swp0", 0))
	require.True(t, pgSweptOf(t, db, "swp1", 0))
	require.True(t, pgSweptOf(t, db, "swp2", 0))
	require.False(t, pgSweptOf(t, db, "uns0", 0))
	require.True(t, pgSweptOf(t, db, "ckpt0", 0))
	before := pgCountSwept(t, db)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	require.True(t, pgSweptOf(t, db, "swp0", 0))
	require.True(t, pgSweptOf(t, db, "swp1", 0))
	require.True(t, pgSweptOf(t, db, "swp2", 0))
	require.False(t, pgSweptOf(t, db, "uns0", 0))
	require.False(t, pgSweptOf(t, db, "uns1", 0))
	require.True(t, pgSweptOf(t, db, "ckpt0", 0))
	require.Equal(t, before, pgCountSwept(t, db))

	var smCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM swept_marker`).Scan(&smCount))
	require.Equal(t, 0, smCount)

	sv := map[string]bool{}
	rows, err := db.Query(`SELECT txid FROM swept_vtxo`)
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

func TestVtxoMarkerMigration_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)
	pgSeedFixtures(t, db)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	snap := func() (string, string, string, string) {
		return pgDumpTable(t, db, `SELECT id, depth, parent_markers::text FROM marker ORDER BY id`),
			pgDumpTable(t, db, `SELECT txid, vout, depth, markers::text FROM vtxo ORDER BY txid, vout`),
			pgDumpTable(t, db, `SELECT marker_id FROM swept_marker ORDER BY marker_id`),
			pgDumpTable(t, db, `SELECT txid, vout FROM swept_vtxo ORDER BY txid, vout`)
	}
	m1, v1, sm1, sv1 := snap()

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	m2, v2, sm2, sv2 := snap()

	require.Equal(t, m1, m2)
	require.Equal(t, v1, v2)
	require.Equal(t, sm1, sm2)
	require.Equal(t, sv1, sv2)
}

func TestVtxoMarkerMigration_DataGuardTripwire(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)
	pgSeedFixtures(t, db)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	pgInsertLegacyVtxo(t, db, "trip0", 0, "", false)
	require.Equal(t, []string{"trip0:0"}, pgMarkersOf(t, db, "trip0", 0))
	require.Equal(t, 0, pgDepthOf(t, db, "trip0", 0))

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	require.Equal(t, []string{"trip0:0"}, pgMarkersOf(t, db, "trip0", 0))
}

func TestVtxoMarkerMigration_EmptyDB(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	var total, latch int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM marker`).Scan(&total))
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM marker WHERE id = '__vtxo_markers_backfill_done__'`,
	).Scan(&latch))
	require.Equal(t, 1, latch)
	require.Equal(t, 1, total)
}

func TestVtxoMarkerMigration_ShallowDAG(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)

	sh := []string{"sh0", "sh1", "sh2"}
	for i, txid := range sh {
		ark := ""
		if i < len(sh)-1 {
			ark = sh[i+1]
		}
		pgInsertLegacyVtxo(t, db, txid, 0, ark, false)
	}

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	require.True(t, pgMarkerExists(t, db, vtxoMarkerBackfillDoneID))

	snap := pgDumpTable(t, db, `SELECT txid, vout, depth, markers::text FROM vtxo ORDER BY txid, vout`)
	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	require.Equal(t, snap, pgDumpTable(t, db, `SELECT txid, vout, depth, markers::text FROM vtxo ORDER BY txid, vout`))
}

func TestVtxoMarkerMigration_SweptCountVerify(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)

	_, err := db.Exec(`INSERT INTO marker (id, depth, parent_markers) VALUES ('shared:0', 0, '[]'::jsonb)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO swept_marker (marker_id, swept_at) VALUES ('shared:0', 5)`)
	require.NoError(t, err)
	for _, txid := range []string{"sha", "shb"} {
		_, err = db.Exec(`
			INSERT INTO vtxo (txid, vout, pubkey, amount, expires_at, created_at,
				commitment_txid, spent, unrolled, preconfirmed, ark_txid, depth, markers)
			VALUES ($1, 0, 'pk', 1, 0, 0, 'c', false, false, false, NULL, 0, '["shared:0"]'::jsonb)`, txid)
		require.NoError(t, err)
	}

	before := pgCountSwept(t, db)
	require.Equal(t, 2, before)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))

	require.Equal(t, before, pgCountSwept(t, db))
	require.True(t, pgSweptOf(t, db, "sha", 0))
	require.True(t, pgSweptOf(t, db, "shb", 0))

	var svc int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM swept_vtxo WHERE txid IN ('sha','shb')`,
	).Scan(&svc))
	require.Equal(t, 2, svc)
}

func TestVtxoMarkerMigration_Wiring(t *testing.T) {
	ctx := context.Background()
	db := newMarkerMigratedPgDB(t)
	pgSeedFixtures(t, db)

	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	require.True(t, pgMarkerExists(t, db, vtxoMarkerBackfillDoneID))

	first := pgDumpTable(t, db, `SELECT id, depth, parent_markers::text FROM marker ORDER BY id`)
	require.NoError(t, pgdb.BackfillVtxoMarkers(ctx, db))
	require.Equal(t, first, pgDumpTable(t, db, `SELECT id, depth, parent_markers::text FROM marker ORDER BY id`))
}

// newMarkerMigratedPgDB opens the pg test DB, drops any prior schema, and
// migrates to the swept_vtxo baseline via the real embedded migration source.
func newMarkerMigratedPgDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", vtxoMarkerPgDSN)
	require.NoError(t, err)
	if perr := db.Ping(); perr != nil {
		//nolint:errcheck
		db.Close()
		t.Skipf("postgres not reachable at %s: %v", vtxoMarkerPgDSN, perr)
	}

	// start from a clean public schema so migration state is deterministic.
	_, err = db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	require.NoError(t, err)

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	require.NoError(t, err)
	source, err := iofs.New(vtxoMarkerPgMigrations, "migration")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(vtxoMarkerPgBaseVersion))

	t.Cleanup(func() {
		_, _ = db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
		//nolint:errcheck
		db.Close()
	})
	return db
}

func pgInsertLegacyVtxo(t *testing.T, db *sql.DB, txid string, vout int, arkTxid string, swept bool) {
	t.Helper()
	op := fmt.Sprintf("%s:%d", txid, vout)
	_, err := db.Exec(
		`INSERT INTO marker (id, depth, parent_markers) VALUES ($1, 0, '[]'::jsonb)
		 ON CONFLICT (id) DO NOTHING`, op,
	)
	require.NoError(t, err)

	var ark any
	if arkTxid != "" {
		ark = arkTxid
	}
	_, err = db.Exec(`
		INSERT INTO vtxo (
			txid, vout, pubkey, amount, expires_at, created_at, commitment_txid,
			spent, unrolled, preconfirmed, ark_txid, depth, markers
		) VALUES ($1, $2, 'pk', 1000, 0, 0, 'commit', false, false, false, $3, 0, $4::jsonb)`,
		txid, vout, ark, fmt.Sprintf(`["%s"]`, op),
	)
	require.NoError(t, err)

	if swept {
		_, err = db.Exec(
			`INSERT INTO swept_marker (marker_id, swept_at) VALUES ($1, $2)
			 ON CONFLICT (marker_id) DO NOTHING`, op, 111,
		)
		require.NoError(t, err)
	}
}

func pgSeedFixtures(t *testing.T, db *sql.DB) []string {
	t.Helper()
	const n = 205
	main := make([]string, n+1)
	for k := 0; k <= n; k++ {
		main[k] = fmt.Sprintf("main%04d", k)
	}
	for k := 0; k <= n; k++ {
		ark := ""
		if k < n {
			ark = main[k+1]
		}
		pgInsertLegacyVtxo(t, db, main[k], 0, ark, false)
	}

	swp := []string{"swp0", "swp1", "swp2"}
	for i, txid := range swp {
		ark := ""
		if i < len(swp)-1 {
			ark = swp[i+1]
		}
		pgInsertLegacyVtxo(t, db, txid, 0, ark, true)
	}

	uns := []string{"uns0", "uns1"}
	for i, txid := range uns {
		ark := ""
		if i < len(uns)-1 {
			ark = uns[i+1]
		}
		pgInsertLegacyVtxo(t, db, txid, 0, ark, false)
	}

	pgInsertLegacyVtxo(t, db, "ckpt0", 0, "", false)
	_, err := db.Exec(`INSERT INTO swept_vtxo (txid, vout, swept_at) VALUES ('ckpt0', 0, 999)`)
	require.NoError(t, err)

	pgInsertLegacyVtxo(t, db, "orph0", 0, "prunedparent", false)
	return main
}

func pgMarkersOf(t *testing.T, db *sql.DB, txid string, vout int) []string {
	t.Helper()
	rows, err := db.Query(
		`SELECT j.value FROM vtxo v, jsonb_array_elements_text(v.markers) j
		 WHERE v.txid = $1 AND v.vout = $2`, txid, vout,
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

func pgDepthOf(t *testing.T, db *sql.DB, txid string, vout int) int {
	t.Helper()
	var d int
	require.NoError(t, db.QueryRow(
		`SELECT depth FROM vtxo WHERE txid = $1 AND vout = $2`, txid, vout,
	).Scan(&d))
	return d
}

func pgSweptOf(t *testing.T, db *sql.DB, txid string, vout int) bool {
	t.Helper()
	var s bool
	require.NoError(t, db.QueryRow(
		`SELECT swept FROM vtxo_vw WHERE txid = $1 AND vout = $2`, txid, vout,
	).Scan(&s))
	return s
}

func pgCountSwept(t *testing.T, db *sql.DB) int {
	t.Helper()
	var c int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM vtxo_vw WHERE swept = true`).Scan(&c))
	return c
}

func pgMarkerExists(t *testing.T, db *sql.DB, id string) bool {
	t.Helper()
	var c int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM marker WHERE id = $1`, id).Scan(&c))
	return c > 0
}

func pgDumpTable(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.Query(query)
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

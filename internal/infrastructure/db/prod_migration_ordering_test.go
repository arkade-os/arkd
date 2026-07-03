package db_test

import (
	"database/sql"
	"embed"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

//go:embed postgres/migration/*
var pgMigrationsOrderingCheck embed.FS

// TestProdMigrationOrdering_DAGSchemaSkipped runs the branch's full postgres
// migration set against a scratch DB restored from a real prod dump (which sits
// at a migration version LATER than the DAG schema migrations) and checks
// whether the marker/depth/swept schema actually gets created.
//
// Gated behind PROD_SCRATCH_DSN so it never runs in normal CI:
//
//	PROD_SCRATCH_DSN='postgresql://postgres:demo@127.0.0.1:5434/projection?sslmode=disable' \
//	  go test ./internal/infrastructure/db/ -run TestProdMigrationOrdering -v
func TestProdMigrationOrdering_DAGSchemaSkipped(t *testing.T) {
	dsn := os.Getenv("PROD_SCRATCH_DSN")
	if dsn == "" {
		t.Skip("set PROD_SCRATCH_DSN (scratch postgres restored from a prod dump)")
	}

	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, db.Ping())

	tableExists := func(name string) bool {
		var ok bool
		require.NoError(t, db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables
			 WHERE table_schema='public' AND table_name=$1)`, name).Scan(&ok))
		return ok
	}
	colExists := func(tbl, col string) bool {
		var ok bool
		require.NoError(t, db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM information_schema.columns
			 WHERE table_schema='public' AND table_name=$1 AND column_name=$2)`,
			tbl, col).Scan(&ok))
		return ok
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	require.NoError(t, err)
	src, err := iofs.New(pgMigrationsOrderingCheck, "postgres/migration")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	require.NoError(t, err)

	vBefore, _, _ := m.Version()
	t.Logf("BEFORE  version=%d  marker=%v  vtxo.depth=%v  swept_vtxo=%v",
		vBefore, tableExists("marker"), colExists("vtxo", "depth"), tableExists("swept_vtxo"))

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		require.NoError(t, err)
	}
	vAfter, _, _ := m.Version()

	markerAfter := tableExists("marker")
	t.Logf("AFTER   version=%d  marker=%v  vtxo.depth=%v  swept_vtxo=%v",
		vAfter, markerAfter, colExists("vtxo", "depth"), tableExists("swept_vtxo"))

	if !markerAfter {
		t.Errorf("\n*** CONFIRMED: after m.Up() the DAG schema (marker/depth/swept) is STILL MISSING.\n"+
			"    add_vtxo_marker_dag(20260701000000) is below the prod version (%d), so\n"+
			"    golang-migrate skipped it. The DAG feature would deploy to prod with no\n"+
			"    marker schema -> broken.", vBefore)
	} else {
		t.Logf("marker schema present after m.Up() (migrations applied in order)")
	}
}

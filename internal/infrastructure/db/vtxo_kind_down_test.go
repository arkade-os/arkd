package db_test

import (
	"database/sql"
	"embed"
	"fmt"
	"testing"

	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/require"
)

const (
	addVtxoKindMigrationVersion = 20260901000000
	// addVtxoKindPostgresDsn names a database this test owns on the same test
	// server TestService uses, so the two never share state.
	addVtxoKindPostgresDsn = "postgresql://root:secret@127.0.0.1:5432/vtxo_kind_migration?sslmode=disable"
)

// TestAddVtxoKindDownMigration verifies the add_vtxo_kind migration is
// reversible on both SQL backends: up adds the vtxo_kind column and surfaces
// it through vtxo_vw, down drops the column and recreates the views without
// it, and a re-apply works cleanly.
func TestAddVtxoKindDownMigration(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		m, db := newSweptVtxoMigrator(t)
		t.Cleanup(func() {
			//nolint:errcheck
			db.Close()
		})
		testAddVtxoKindDownMigration(t, m, sqliteSchema{db})
	})

	t.Run("postgres", func(t *testing.T) {
		m, db := newVtxoKindPostgresMigrator(t)
		t.Cleanup(func() {
			//nolint:errcheck
			db.Close()
		})
		testAddVtxoKindDownMigration(t, m, postgresSchema{db})
	})
}

func testAddVtxoKindDownMigration(t *testing.T, m *migrate.Migrate, s schema) {
	require.NoError(t, m.Migrate(addVtxoKindMigrationVersion))

	// Up: vtxo_kind exists on the base table and is visible through vtxo_vw.
	require.True(t, s.hasColumn(t, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should exist after the up migration")
	require.True(t, s.hasColumn(t, "vtxo_vw", "vtxo_kind"),
		"vtxo_vw should expose vtxo_kind after the up migration")

	// Down one step reverses add_vtxo_kind.
	require.NoError(t, m.Steps(-1), "down migration must succeed")
	require.False(t, s.hasColumn(t, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should be gone after the down migration")
	require.False(t, s.hasColumn(t, "vtxo_vw", "vtxo_kind"),
		"vtxo_vw should not expose vtxo_kind after the down migration")
	require.True(t, s.viewExists(t, "vtxo_vw"),
		"vtxo_vw should be recreated by the down migration")

	// Re-applying forward must succeed.
	require.NoError(t, m.Steps(1), "re-applying the up migration must succeed")
	require.True(t, s.hasColumn(t, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should exist again after re-applying")
}

// --- helpers ---

//go:embed postgres/migration/*
var vtxoKindPostgresMigrations embed.FS

// schema inspects a backend's catalog for the columns and views the test
// asserts on.
type schema interface {
	hasColumn(t *testing.T, table, column string) bool
	viewExists(t *testing.T, name string) bool
}

// newVtxoKindPostgresMigrator opens the test's own postgres database, creating
// it if needed, wipes whatever a previous run left in it, and returns a
// migrate.Migrate bound to the embedded postgres migration source.
func newVtxoKindPostgresMigrator(t *testing.T) (*migrate.Migrate, *sql.DB) {
	t.Helper()
	db, err := pgdb.OpenDb(addVtxoKindPostgresDsn, true)
	require.NoError(t, err)

	newMigrator := func() *migrate.Migrate {
		driver, err := migratepg.WithInstance(db, &migratepg.Config{})
		require.NoError(t, err)
		source, err := iofs.New(vtxoKindPostgresMigrations, "postgres/migration")
		require.NoError(t, err)
		m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
		require.NoError(t, err)
		return m
	}

	// Drop invalidates the instance it ran on, so build a fresh one after it.
	require.NoError(t, newMigrator().Drop())
	return newMigrator(), db
}

type sqliteSchema struct{ db *sql.DB }

func (s sqliteSchema) hasColumn(t *testing.T, table, column string) bool {
	return hasColumn(t, s.db, table, column)
}

func (s sqliteSchema) viewExists(t *testing.T, name string) bool {
	return viewExists(t, s.db, name)
}

type postgresSchema struct{ db *sql.DB }

// hasColumn reads information_schema.columns, which lists view columns as
// well as table columns.
func (s postgresSchema) hasColumn(t *testing.T, table, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, s.db.QueryRow(
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column,
	).Scan(&n))
	return n > 0
}

func (s postgresSchema) viewExists(t *testing.T, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, s.db.QueryRow(
		`SELECT count(*) FROM information_schema.views
		 WHERE table_schema = current_schema() AND table_name = $1`, name,
	).Scan(&n))
	return n > 0
}

// hasColumn reports whether the given table or view exposes a column, via
// sqlite's PRAGMA table_info (which works for views too).
func hasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notnull, pk int
			dflt        sql.NullString
		)
		require.NoError(t, rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk))
		if name == column {
			return true
		}
	}
	require.NoError(t, rows.Err())
	return false
}

// viewExists reports whether a view of the given name exists.
func viewExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var got string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='view' AND name=?", name,
	).Scan(&got)
	if err == sql.ErrNoRows {
		return false
	}
	require.NoError(t, err)
	return got == name
}

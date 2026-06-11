package db_test

import (
	"database/sql"
	"embed"
	"strings"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/require"
)

//go:embed sqlite/migration/*
var sweptVtxoTestMigrations embed.FS

const sweptVtxoMigrationVersion = 20260416120000

// TestSweptVtxoDownMigration_Guard verifies that the sqlite down migration
// for 20260416120000_add_swept_vtxo aborts when swept_vtxo has data (to
// prevent silently resurrecting swept VTXOs) but proceeds cleanly when the
// table is empty.
func TestSweptVtxoDownMigration_Guard(t *testing.T) {
	t.Run("aborts_when_swept_vtxo_has_data", func(t *testing.T) {
		m, db := newSweptVtxoMigrator(t)
		t.Cleanup(func() {
			// Force the version so cleanup doesn't complain about a dirty
			// migration state left by the expected failure.
			_ = m.Force(sweptVtxoMigrationVersion)
			//nolint:errcheck
			db.Close()
		})

		require.NoError(t, m.Migrate(sweptVtxoMigrationVersion))

		_, err := db.Exec(
			`INSERT INTO swept_vtxo (txid, vout, swept_at) VALUES (?, ?, ?)`,
			"deadbeef", 0, 1234567890,
		)
		require.NoError(t, err, "seed insert must succeed before the guard test")

		// Stepping back one migration should fail: the guard trigger fires
		// because swept_vtxo has a row.
		err = m.Steps(-1)
		require.Error(t, err, "down migration must abort when swept_vtxo is non-empty")
		require.True(t,
			strings.Contains(err.Error(), "irreversible migration") ||
				strings.Contains(err.Error(), "swept_vtxo"),
			"error should mention the guard: got %v", err,
		)

		// swept_vtxo must still exist and still contain the row — the
		// transaction aborted before the DROP ran.
		var count int
		err = db.QueryRow(`SELECT count(*) FROM swept_vtxo`).Scan(&count)
		require.NoError(t, err,
			"swept_vtxo should still exist after the aborted down migration")
		require.Equal(t, 1, count,
			"swept_vtxo data must be preserved when the guard fires")
	})

	t.Run("proceeds_when_swept_vtxo_is_empty", func(t *testing.T) {
		m, db := newSweptVtxoMigrator(t)
		t.Cleanup(func() {
			//nolint:errcheck
			db.Close()
		})

		require.NoError(t, m.Migrate(sweptVtxoMigrationVersion))

		// swept_vtxo exists but is empty — the guard should not fire.
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM swept_vtxo`).Scan(&count))
		require.Equal(t, 0, count)

		require.NoError(t, m.Steps(-1),
			"down migration must succeed when swept_vtxo is empty")

		// swept_vtxo should be gone; vtxo_vw should still exist (restored by
		// the down migration body that runs past the guard).
		err := db.QueryRow(`SELECT count(*) FROM swept_vtxo`).Scan(&count)
		require.Error(t, err, "swept_vtxo should have been dropped")
		require.Contains(t, err.Error(), "no such table")

		rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='view' AND name='vtxo_vw'`)
		require.NoError(t, err)
		defer rows.Close()
		require.True(t, rows.Next(),
			"vtxo_vw view should have been recreated by the down migration")
	})
}

// newSweptVtxoMigrator returns a fresh in-memory sqlite DB paired with a
// migrate.Migrate bound to the embedded sqlite migration source.
func newSweptVtxoMigrator(t *testing.T) (*migrate.Migrate, *sql.DB) {
	t.Helper()
	db, err := sqlitedb.OpenDb(":memory:")
	require.NoError(t, err)

	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	require.NoError(t, err)

	source, err := iofs.New(sweptVtxoTestMigrations, "sqlite/migration")
	require.NoError(t, err)

	m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
	require.NoError(t, err)

	return m, db
}

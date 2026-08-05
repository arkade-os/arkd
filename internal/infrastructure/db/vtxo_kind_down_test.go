package db_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const addVtxoKindMigrationVersion = 20260724000000

// TestAddVtxoKindDownMigration verifies the add_vtxo_kind migration is
// reversible: up adds the vtxo_kind column and surfaces it through vtxo_vw,
// down drops the column and recreates the views without it, and a re-apply
// works cleanly.
func TestAddVtxoKindDownMigration(t *testing.T) {
	m, db := newSweptVtxoMigrator(t)
	t.Cleanup(func() {
		//nolint:errcheck
		db.Close()
	})

	require.NoError(t, m.Migrate(addVtxoKindMigrationVersion))

	// Up: vtxo_kind exists on the base table and is visible through vtxo_vw.
	require.True(t, hasColumn(t, db, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should exist after the up migration")
	require.True(t, hasColumn(t, db, "vtxo_vw", "vtxo_kind"),
		"vtxo_vw should expose vtxo_kind after the up migration")

	// Down one step reverses add_vtxo_kind.
	require.NoError(t, m.Steps(-1), "down migration must succeed")
	require.False(t, hasColumn(t, db, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should be gone after the down migration")
	require.False(t, hasColumn(t, db, "vtxo_vw", "vtxo_kind"),
		"vtxo_vw should not expose vtxo_kind after the down migration")
	require.True(t, viewExists(t, db, "vtxo_vw"),
		"vtxo_vw should be recreated by the down migration")

	// Re-applying forward must succeed.
	require.NoError(t, m.Steps(1), "re-applying the up migration must succeed")
	require.True(t, hasColumn(t, db, "vtxo", "vtxo_kind"),
		"vtxo.vtxo_kind should exist again after re-applying")
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

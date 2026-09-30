package sqlitedb_test

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

//go:embed migration/*
var assetJoinMigrations embed.FS

func TestVtxoAssetJoinMigration(t *testing.T) {
	db, err := sqlitedb.OpenDb("file::memory:", sqlitedb.WithSharedCache())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	driver, err := sqlitemigrate.WithInstance(db.Write(), &sqlitemigrate.Config{})
	require.NoError(t, err)
	source, err := iofs.New(assetJoinMigrations, "migration")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(20260807120000))

	insertLegacyVtxo(t, db.Write(), "asset-join", 0, "", false)
	_, err = db.Write().Exec(`UPDATE vtxo SET updated_at = 1 WHERE txid = 'asset-join' AND vout = 0`)
	require.NoError(t, err)
	for _, id := range []string{"asset-a", "asset-b"} {
		_, err = db.Write().Exec(`INSERT INTO asset (id, is_immutable) VALUES (?, 1)`, id)
		require.NoError(t, err)
		_, err = db.Write().Exec(`INSERT INTO asset_projection (asset_id, txid, vout, amount) VALUES (?, 'asset-join', 0, 20)`, id)
		require.NoError(t, err)
	}

	before := assetRows(t, db.Read())
	require.Equal(t, []string{"asset-a:20", "asset-b:20"}, before)
	require.Contains(t, queryPlan(t, db.Read()), "MATERIALIZE ap")

	require.NoError(t, m.Steps(1))
	require.Equal(t, before, assetRows(t, db.Read()))
	plan := queryPlan(t, db.Read())
	require.NotContains(t, plan, "MATERIALIZE ap")
	require.Contains(t, plan, "SEARCH ap USING INDEX idx_asset_projection_vtxo")

	require.NoError(t, m.Steps(-1))
	require.Equal(t, before, assetRows(t, db.Read()))
	require.Contains(t, queryPlan(t, db.Read()), "MATERIALIZE ap")
}

func assetRows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT asset_id, CAST(asset_amount AS TEXT) FROM vtxo_vw WHERE pubkey = 'pk' AND updated_at >= 0 ORDER BY asset_id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, amount string
		require.NoError(t, rows.Scan(&id, &amount))
		out = append(out, id+":"+amount)
	}
	require.NoError(t, rows.Err())
	return out
}

func queryPlan(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT * FROM vtxo_vw WHERE pubkey = 'pk' AND updated_at >= 0`)
	require.NoError(t, err)
	defer rows.Close()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &unused, &detail))
		steps = append(steps, detail)
	}
	require.NoError(t, rows.Err())
	return strings.Join(steps, "\n")
}

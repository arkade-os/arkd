package sqlitedb_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/stretchr/testify/require"
)

// TestGetTxsWithTxidsBatched drives the multi-batch path of the unexported
// helper with small batch sizes against an in-memory sqlite DB. Guards
// against off-by-one errors in start/end slicing and missed dedup across
// batch boundaries when the input itself contains duplicated txids.
func TestGetTxsWithTxidsBatched(t *testing.T) {
	ctx := context.Background()
	// Per-test file-backed DB: the split read/write pools (see OpenDb)
	// both see the same database without shared-cache in-memory mode,
	// whose process-global name registry is shared with every other test
	// in this package.
	dbSvc, err := sqlitedb.OpenDb(filepath.Join(t.TempDir(), "batching_test.db"))
	require.NoError(t, err)
	db := dbSvc.Write()
	t.Cleanup(func() {
		//nolint:errcheck
		dbSvc.Close()
	})

	setupTxTables(t, db)

	// Four tree txs, three offchain txs, two checkpoint txs.
	txids := make([]string, 0, 9)
	expected := make(map[string]struct{})
	for i := 0; i < 4; i++ {
		txid := fmt.Sprintf("tx-%02d", i)
		insertTxRow(t, db, "tx", txid, "data-"+txid)
		txids = append(txids, txid)
		expected["data-"+txid] = struct{}{}
	}
	for i := 0; i < 3; i++ {
		txid := fmt.Sprintf("offchain-%02d", i)
		insertTxRow(t, db, "offchain_tx", txid, "data-"+txid)
		txids = append(txids, txid)
		expected["data-"+txid] = struct{}{}
	}
	for i := 0; i < 2; i++ {
		txid := fmt.Sprintf("checkpoint-%02d", i)
		insertTxRow(t, db, "checkpoint_tx", txid, "data-"+txid)
		txids = append(txids, txid)
		expected["data-"+txid] = struct{}{}
	}
	// A duplicated txid lands in a different batch for small batch sizes,
	// forcing the cross-batch dedup path; an unknown txid must be ignored.
	txids = append(txids, "tx-00", "unknown-txid")

	repo, err := sqlitedb.NewRoundRepository(dbSvc)
	require.NoError(t, err)

	// 1, 2, 3 force the multi-batch loop; len-1 leaves a short tail batch;
	// len and len+1 produce a single batch; 0 must fall through to the
	// "no batching" branch.
	for _, batchSize := range []int{1, 2, 3, len(txids) - 1, len(txids), len(txids) + 1, 0} {
		got, err := sqlitedb.GetTxsWithTxidsBatched(ctx, repo, txids, batchSize)
		require.NoErrorf(t, err, "batchSize=%d", batchSize)
		gotSet := make(map[string]struct{}, len(got))
		for _, k := range got {
			gotSet[k] = struct{}{}
		}
		require.Equalf(t, len(got), len(gotSet),
			"batchSize=%d: duplicates in result", batchSize)
		require.Truef(t, reflect.DeepEqual(gotSet, expected),
			"batchSize=%d: union mismatch (got %d unique, want %d)",
			batchSize, len(gotSet), len(expected))
	}
}

// TestGetTxsWithTxidsOverVariableLimit exercises the public method with more
// txids than a single query can bind: SelectTxs expands the slice into three
// IN clauses (3N params) and sqlite caps a statement at
// SQLITE_MAX_VARIABLE_NUMBER = 32766, so 12000 txids would need 36000 params
// in one query and fail with "too many SQL variables" without batching.
func TestGetTxsWithTxidsOverVariableLimit(t *testing.T) {
	ctx := context.Background()
	// Per-test file-backed DB; see the sibling test for the rationale.
	dbSvc, err := sqlitedb.OpenDb(filepath.Join(t.TempDir(), "bulk_test.db"))
	require.NoError(t, err)
	db := dbSvc.Write()
	t.Cleanup(func() {
		//nolint:errcheck
		dbSvc.Close()
	})

	setupTxTables(t, db)

	const total = 12000
	txids := make([]string, 0, total)
	expected := make(map[string]struct{}, total)
	tx, err := db.Begin()
	require.NoError(t, err)
	for i := 0; i < total; i++ {
		txid := fmt.Sprintf("bulk-%05d", i)
		_, err := tx.Exec(
			"INSERT INTO tx (txid, tx, round_id, type, position) VALUES (?, ?, ?, ?, ?)",
			txid, "data-"+txid, "round-1", "tree", i,
		)
		require.NoError(t, err)
		txids = append(txids, txid)
		expected["data-"+txid] = struct{}{}
	}
	require.NoError(t, tx.Commit())

	repo, err := sqlitedb.NewRoundRepository(dbSvc)
	require.NoError(t, err)

	got, err := repo.GetTxsWithTxids(ctx, txids)
	require.NoError(t, err)
	require.Len(t, got, total)
	gotSet := make(map[string]struct{}, len(got))
	for _, k := range got {
		gotSet[k] = struct{}{}
	}
	require.True(t, reflect.DeepEqual(gotSet, expected))
}

func setupTxTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tx (
			txid TEXT PRIMARY KEY,
			tx TEXT NOT NULL,
			round_id TEXT NOT NULL,
			type TEXT NOT NULL,
			position INTEGER NOT NULL,
			children TEXT
		);
		CREATE TABLE IF NOT EXISTS offchain_tx (
			txid TEXT PRIMARY KEY,
			tx TEXT NOT NULL,
			starting_timestamp BIGINT NOT NULL DEFAULT 0,
			ending_timestamp BIGINT NOT NULL DEFAULT 0,
			expiry_timestamp BIGINT NOT NULL DEFAULT 0,
			fail_reason TEXT,
			stage_code INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS checkpoint_tx (
			txid TEXT PRIMARY KEY,
			tx TEXT NOT NULL,
			commitment_txid TEXT NOT NULL DEFAULT '',
			is_root_commitment_txid BOOLEAN NOT NULL DEFAULT FALSE,
			offchain_txid TEXT NOT NULL DEFAULT ''
		);
	`)
	require.NoError(t, err)
}

func insertTxRow(t *testing.T, db *sql.DB, table, txid, data string) {
	t.Helper()
	var err error
	switch table {
	case "tx":
		_, err = db.Exec(
			"INSERT INTO tx (txid, tx, round_id, type, position) VALUES (?, ?, ?, ?, ?)",
			txid, data, "round-1", "tree", 0,
		)
	case "offchain_tx":
		_, err = db.Exec(
			"INSERT INTO offchain_tx (txid, tx) VALUES (?, ?)",
			txid, data,
		)
	case "checkpoint_tx":
		_, err = db.Exec(
			"INSERT INTO checkpoint_tx (txid, tx) VALUES (?, ?)",
			txid, data,
		)
	default:
		t.Fatalf("unknown table %s", table)
	}
	require.NoError(t, err)
}

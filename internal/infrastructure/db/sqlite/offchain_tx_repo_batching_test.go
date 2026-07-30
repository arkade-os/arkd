package sqlitedb_test

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/stretchr/testify/require"
)

// TestGetOffchainTxsByTxidsBatching drives the WithTxids path of
// GetOffchainTxs past sqliteMaxBulkTxids. The SLICE expansion emits one
// bound parameter per txid, so an unbatched query would either blow past
// SQLITE_MAX_VARIABLE_NUMBER or, once batched, lose the query's global
// ORDER BY across batch boundaries.
func TestGetOffchainTxsByTxidsBatching(t *testing.T) {
	ctx := context.Background()

	// Enough rows to force multiple batches at the 500 cap.
	const rowCount = 1201

	dbSvc, err := sqlitedb.OpenDb("file::memory:", sqlitedb.WithSharedCache())
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbSvc.Close() })
	setupOffchainTxSchema(t, dbSvc.Write())

	// Timestamps must NOT be monotonic in the txid, or each batch would
	// already hold a contiguous descending block and simple concatenation
	// would look correctly ordered. 997 is coprime to 600, so this scatters
	// timestamps across every batch, and the modulus is smaller than
	// rowCount so timestamps repeat and the txid ASC tiebreak is exercised
	// across batch boundaries too.
	txids := make([]string, 0, rowCount)
	for i := range rowCount {
		txid := fmt.Sprintf("txid-%05d", i)
		txids = append(txids, txid)
		insertOffchainTxRow(t, dbSvc.Write(), txid, int64((i*997)%600))
	}

	repo, err := sqlitedb.NewOffchainTxRepository(dbSvc)
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	got, err := repo.GetOffchainTxs(ctx, domain.OffchainTxFilter{WithTxids: txids})
	require.NoError(t, err)
	require.Len(t, got, rowCount, "every requested txid must survive batching")

	// The contract is ORDER BY starting_timestamp DESC, txid ASC.
	require.True(t, sort.SliceIsSorted(got, func(i, j int) bool {
		if got[i].StartingTimestamp != got[j].StartingTimestamp {
			return got[i].StartingTimestamp > got[j].StartingTimestamp
		}
		return got[i].ArkTxid < got[j].ArkTxid
	}), "results must stay globally ordered across batch boundaries")

	// No txid is dropped or duplicated by the batch slicing.
	seen := make(map[string]struct{}, len(got))
	for _, off := range got {
		_, dup := seen[off.ArkTxid]
		require.False(t, dup, "duplicate txid %s", off.ArkTxid)
		seen[off.ArkTxid] = struct{}{}
	}
	require.Len(t, seen, rowCount)

	// A single-batch request keeps working unchanged.
	head := txids[:10]
	got, err = repo.GetOffchainTxs(ctx, domain.OffchainTxFilter{WithTxids: head})
	require.NoError(t, err)
	require.Len(t, got, len(head))
}

func setupOffchainTxSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS offchain_tx (
            txid TEXT PRIMARY KEY,
            tx TEXT NOT NULL,
            starting_timestamp INTEGER NOT NULL,
            ending_timestamp INTEGER NOT NULL,
            expiry_timestamp INTEGER NOT NULL,
            fail_reason TEXT,
            stage_code INTEGER NOT NULL,
            packets TEXT
        );
        CREATE TABLE IF NOT EXISTS checkpoint_tx (
            txid TEXT PRIMARY KEY,
            tx TEXT NOT NULL,
            commitment_txid TEXT NOT NULL,
            is_root_commitment_txid BOOLEAN NOT NULL DEFAULT FALSE,
            offchain_txid TEXT NOT NULL,
            FOREIGN KEY (offchain_txid) REFERENCES offchain_tx(txid)
        );
        DROP VIEW IF EXISTS offchain_tx_vw;
        CREATE VIEW offchain_tx_vw AS
        SELECT
            offchain_tx.*,
            COALESCE(checkpoint_tx.txid, '') AS checkpoint_txid,
            COALESCE(checkpoint_tx.tx, '') AS checkpoint_tx,
            checkpoint_tx.commitment_txid,
            checkpoint_tx.is_root_commitment_txid,
            checkpoint_tx.offchain_txid
        FROM offchain_tx
            LEFT JOIN checkpoint_tx
            ON offchain_tx.txid = checkpoint_tx.offchain_txid;
    `)
	require.NoError(t, err, "failed to create offchain_tx schema")
}

// insertOffchainTxRow adds an accepted (stage_code 2) row with a
// non-NULL packets column so the backfill leaves it alone.
func insertOffchainTxRow(t *testing.T, db *sql.DB, txid string, startingTimestamp int64) {
	t.Helper()
	_, err := db.Exec(`
        INSERT INTO offchain_tx
            (txid, tx, starting_timestamp, ending_timestamp, expiry_timestamp,
             fail_reason, stage_code, packets)
        VALUES (?, ?, ?, 0, 0, NULL, 2, '');
    `, txid, "tx-"+txid, startingTimestamp)
	require.NoError(t, err)
}

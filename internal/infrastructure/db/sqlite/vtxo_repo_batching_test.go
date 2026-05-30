package sqlitedb_test

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/stretchr/testify/require"
)

// TestGetVtxoPubKeysByCommitmentTxidsBatched drives the multi-batch path
// of the unexported helper with small batch sizes against an in-memory
// sqlite DB. Guards against off-by-one errors in start/end slicing and
// missed dedup across batch boundaries.
func TestGetVtxoPubKeysByCommitmentTxidsBatched(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitedb.OpenDb(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		//nolint:errcheck
		db.Close()
	})

	setupVtxoTables(t, db)

	// Seed seven commitment txids; each fans out to two vtxos. A handful
	// of pubkeys appear under more than one commitment txid so the dedup
	// path is exercised non-trivially.
	const rounds = 7
	const vtxosPerRound = 2
	commitmentTxids := make([]string, 0, rounds)
	expected := make(map[string]struct{})
	for r := 0; r < rounds; r++ {
		commitmentTxid := fmt.Sprintf("commitment-%02d", r)
		commitmentTxids = append(commitmentTxids, commitmentTxid)
		for v := 0; v < vtxosPerRound; v++ {
			pubkey := fmt.Sprintf("pubkey-%02d-%d", r, v)
			vtxoTxid := fmt.Sprintf("vtxo-%02d-%d", r, v)
			insertVtxoRow(t, db, vtxoTxid, v, pubkey, 1000, commitmentTxid)
			// Cross-link every third vtxo to the previous round's
			// commitment via the join table, so multiple batches can
			// each return the same pubkey and the dedup logic has
			// real work to do.
			if r > 0 && v == 0 {
				insertVtxoCommitmentTxidRow(
					t, db, vtxoTxid, v, commitmentTxids[r-1],
				)
			}
			expected[pubkey] = struct{}{}
		}
	}

	repo, err := sqlitedb.NewVtxoRepository(db)
	require.NoError(t, err)

	// 1, 2, 3 force the multi-batch loop; rounds-1 leaves a short tail
	// batch; rounds and rounds+1 produce a single batch; 0 must fall
	// through to the "no batching" branch.
	for _, batchSize := range []int{1, 2, 3, rounds - 1, rounds, rounds + 1, 0} {
		got, err := sqlitedb.GetVtxoPubKeysByCommitmentTxidsBatched(
			ctx, repo, commitmentTxids, 0, batchSize,
		)
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

// TestGetVtxoPubKeysByCommitmentTxidsBatched_MinAmount verifies the
// withMinimumAmount predicate survives the per-batch query and merge.
func TestGetVtxoPubKeysByCommitmentTxidsBatched_MinAmount(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitedb.OpenDb(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		//nolint:errcheck
		db.Close()
	})

	setupVtxoTables(t, db)

	// Two commitment txids, each with a below-threshold and an
	// above-threshold vtxo. commitment-A also gets a vtxo whose amount
	// equals min_amount to lock the inclusive >= predicate (the badger
	// backend was previously > and is fixed in this PR for parity).
	commitmentTxids := []string{"commitment-A", "commitment-B"}
	insertVtxoRow(t, db, "vtxo-a-low", 0, "pubkey-a-low", 100, commitmentTxids[0])
	insertVtxoRow(t, db, "vtxo-a-eq", 0, "pubkey-a-eq", 1000, commitmentTxids[0])
	insertVtxoRow(t, db, "vtxo-a-high", 0, "pubkey-a-high", 5000, commitmentTxids[0])
	insertVtxoRow(t, db, "vtxo-b-low", 0, "pubkey-b-low", 200, commitmentTxids[1])
	insertVtxoRow(t, db, "vtxo-b-high", 0, "pubkey-b-high", 7500, commitmentTxids[1])

	repo, err := sqlitedb.NewVtxoRepository(db)
	require.NoError(t, err)

	got, err := sqlitedb.GetVtxoPubKeysByCommitmentTxidsBatched(
		ctx, repo, commitmentTxids, 1000, 1,
	)
	require.NoError(t, err)
	require.ElementsMatch(t,
		[]string{"pubkey-a-eq", "pubkey-a-high", "pubkey-b-high"}, got)
}

func setupVtxoTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS vtxo (
			txid TEXT NOT NULL,
			vout INTEGER NOT NULL,
			pubkey TEXT NOT NULL,
			amount INTEGER NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL DEFAULT 0,
			commitment_txid TEXT NOT NULL,
			spent_by TEXT,
			spent BOOLEAN NOT NULL DEFAULT FALSE,
			unrolled BOOLEAN NOT NULL DEFAULT FALSE,
			swept BOOLEAN NOT NULL DEFAULT FALSE,
			preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
			settled_by TEXT,
			ark_txid TEXT,
			intent_id TEXT,
			PRIMARY KEY (txid, vout)
		);
	`)
	require.NoError(t, err, "create vtxo table")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vtxo_commitment_txid (
			vtxo_txid TEXT NOT NULL,
			vtxo_vout INTEGER NOT NULL,
			commitment_txid TEXT NOT NULL,
			PRIMARY KEY (vtxo_txid, vtxo_vout, commitment_txid)
		);
	`)
	require.NoError(t, err, "create vtxo_commitment_txid table")
}

func insertVtxoRow(
	t *testing.T,
	db *sql.DB,
	txid string,
	vout int,
	pubkey string,
	amount int64,
	commitmentTxid string,
) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO vtxo (txid, vout, pubkey, amount, commitment_txid) `+
			`VALUES (?, ?, ?, ?, ?)`,
		txid, vout, pubkey, amount, commitmentTxid,
	)
	require.NoError(t, err, "insert vtxo %s/%d", txid, vout)
}

func insertVtxoCommitmentTxidRow(
	t *testing.T,
	db *sql.DB,
	vtxoTxid string,
	vtxoVout int,
	commitmentTxid string,
) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO vtxo_commitment_txid (vtxo_txid, vtxo_vout, commitment_txid) `+
			`VALUES (?, ?, ?)`,
		vtxoTxid, vtxoVout, commitmentTxid,
	)
	require.NoError(t, err, "insert vtxo_commitment_txid %s/%d", vtxoTxid, vtxoVout)
}

package sqlitedb_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// rawTxTwoPackets is the same fixture used by the domain matcher test:
// a tx carrying an ARK extension with packet types 0 and 255.
const rawTxTwoPackets = "01000000000100000000000000001b6a1941524b000e01020200000001010000c0de810aff04deadbeef00000000"

// rawTxNoExtension is a tx with one non-extension output.
const rawTxNoExtension = "010000000001e803000000000000225120000000000000000000000000000000000000000000000000000000000000000000000000"

func TestBackfillPackets(t *testing.T) {
	ctx := context.Background()

	db, err := sqlitedb.OpenDb(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	setupOffchainTxTableForBackfill(t, db)

	// Three pre-existing rows, all with packets = NULL (the
	// pre-migration state). The backfill should:
	//   * carrier        -> packets = "0,255"
	//   * no-extension   -> packets = ""   (Valid, distinguishes from NULL)
	//   * malformed psbt -> packets = ""   (Valid, marked to avoid retry)
	carrierTxid := insertRow(t, db, "carrier-txid", psbtBase64FromTxHex(t, rawTxTwoPackets))
	noExtTxid := insertRow(t, db, "no-ext-txid", psbtBase64FromTxHex(t, rawTxNoExtension))
	malformedTxid := insertRow(t, db, "malformed-txid", "not-a-psbt")

	require.NoError(t, sqlitedb.BackfillPackets(ctx, db))

	require.Equal(t, "0,255", readPackets(t, db, carrierTxid))
	require.Equal(t, "", readPackets(t, db, noExtTxid))
	require.Equal(t, "", readPackets(t, db, malformedTxid))

	// Re-running should be a no-op: rows with non-NULL packets are not
	// revisited. (Verifies the malformed-row sentinel works.)
	require.NoError(t, sqlitedb.BackfillPackets(ctx, db))

	// And no rows are left with NULL packets.
	var nullCount int
	require.NoError(
		t,
		db.QueryRow(`SELECT COUNT(*) FROM offchain_tx WHERE packets IS NULL`).
			Scan(&nullCount),
	)
	require.Zero(t, nullCount)
}

func setupOffchainTxTableForBackfill(t *testing.T, db *sql.DB) {
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
    `)
	require.NoError(t, err, "failed to create offchain_tx table")
}

func insertRow(t *testing.T, db *sql.DB, txid, txBlob string) string {
	t.Helper()
	_, err := db.Exec(`
        INSERT INTO offchain_tx
            (txid, tx, starting_timestamp, ending_timestamp, expiry_timestamp,
             fail_reason, stage_code, packets)
        VALUES (?, ?, 0, 0, 0, NULL, 2, NULL);
    `, txid, txBlob)
	require.NoError(t, err)
	return txid
}

func readPackets(t *testing.T, db *sql.DB, txid string) string {
	t.Helper()
	var col sql.NullString
	require.NoError(
		t,
		db.QueryRow(`SELECT packets FROM offchain_tx WHERE txid = ?`, txid).Scan(&col),
	)
	require.True(t, col.Valid, "packets must be non-NULL after backfill")
	return col.String
}

// psbtBase64FromTxHex wraps a raw tx hex in a minimal PSBT and returns
// the base64-encoded blob the application layer would have persisted.
func psbtBase64FromTxHex(t *testing.T, txHex string) string {
	t.Helper()
	raw, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	tx := wire.NewMsgTx(wire.TxVersion)
	require.NoError(t, tx.DeserializeNoWitness(bytes.NewReader(raw)))
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

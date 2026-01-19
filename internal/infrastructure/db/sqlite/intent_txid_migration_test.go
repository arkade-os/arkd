package sqlitedb_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

func TestIntentTxidMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitedb.OpenDb(":memory:")
	require.NoError(t, err)

	// nolint:errcheck
	defer db.Close()
	// create table intent references
	setupRoundTable(t, db)
	// create intent table using old schema
	setupOldIntentTable(t, db)

	// insert dummy data into tables
	insertTestRoundRows(t, db)
	insertTestIntentRows(t, db)

	// add new txid field to intent table
	modifyIntentTable(t, db)

	// run the backfill to populate intent rows with derived txids
	err = sqlitedb.BackfillIntentTxid(ctx, db)
	require.NoError(t, err)

	// check the intent table has the new txid column
	var hasID int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('intent') WHERE name = 'txid'`).
		Scan(&hasID)
	require.NoError(t, err)
	require.Equal(t, 1, hasID)

	type row struct {
		ID    string
		Txid  string
		Proof string
	}
	rows, err := db.Query(`
       SELECT id, txid, proof FROM intent;
    `)
	require.NoError(t, err)

	var got []row
	// check we have two rows with txids populated
	for rows.Next() {
		var r row
		err = rows.Scan(&r.ID, &r.Txid, &r.Proof)
		require.NoError(t, err)
		got = append(got, r)
	}

	require.NoError(t, rows.Err())
	require.Len(t, got, 2)

	// nolint:errcheck
	rows.Close()

	// Check each row has a non-empty txid and that it matches the derived txid from the proof
	for _, r := range got {
		require.NotEqual(t, "", r.Txid)
		require.NotEqual(t, "", r.Proof)
		require.NotEqual(t, "", r.ID)

		pkt, err := psbt.NewFromRawBytes(strings.NewReader(r.Proof), true)
		require.NoError(t, err)
		txidFromProof := pkt.UnsignedTx.TxID()
		require.Equal(t, r.Txid, txidFromProof)
	}

}

func setupRoundTable(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS round (
    id TEXT PRIMARY KEY,
    starting_timestamp INTEGER NOT NULL,
    ending_timestamp INTEGER NOT NULL,
    ended BOOLEAN NOT NULL DEFAULT FALSE,
    failed BOOLEAN NOT NULL DEFAULT FALSE,
    stage_code INTEGER NOT NULL,
    connector_address TEXT NOT NULL,
    version INTEGER NOT NULL,
    swept BOOLEAN NOT NULL DEFAULT FALSE,
    vtxo_tree_expiration INTEGER NOT NULL,
    fail_reason TEXT
);`)
	require.NoError(t, err, "failed to create round table")
}

func setupOldIntentTable(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS intent (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL,
    proof TEXT NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

    `)
	require.NoError(t, err, "failed to create old intent table")
}

func modifyIntentTable(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
				ALTER TABLE intent ADD COLUMN txid TEXT;
		`)
	require.NoError(t, err, "failed to modify intent table")
}

func insertTestRoundRows(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
				INSERT INTO round (id, starting_timestamp, ending_timestamp, ended, failed, stage_code, connector_address, version, swept, vtxo_tree_expiration, fail_reason) VALUES 
				('round-1', 1620000000, 1620003600, 1, 0, 3, 'connector-1', 1, 1, 1620007200, NULL),
				('round-2', 1620003600, 1620007200, 1, 0, 3, 'connector-2', 1, 1, 1620010800, NULL);
	`)
	require.NoError(t, err, "failed to insert test round rows")
}

func insertTestIntentRows(t *testing.T, db *sql.DB) {
	// insert two old-style intent rows (no txid column)
	_, err := db.Exec(`
        INSERT INTO intent (id, round_id, proof, message) VALUES
        ('6b2705d5-d09d-4002-84e1-b537709ecea9', 'round-1', 'cHNidP8BALACAAAAAyLh21ahYqxWy2slXY09ZoLvYWKFo7R0zPtbnJqkSUq6AAAAAAAAAAAA9PRZ58PC4lJAJ7VEYtMMUC1E+poh/Gxo+0TNqvgh27wAAAAAAAAAAABRRy0Q2j/vH4YYRfWfzzF4LBB1xX+tQdFOIWTU6ZD0CwMAAAAAAAAAAAHoAwAAAAAAACJRILnf7Ax3APvapTeZQTkWKOBDpi3RdSHKwPmm0Ts+VOa6AAAAAAABASsAAAAAAAAAACJRILnf7Ax3APvapTeZQTkWKOBDpi3RdSHKwPmm2Ds+VObKAQMEAQAAAAABASvoAwAAAAAAACJRILnf7Ax3APvapTeZQTkWKOBDpi3RdSHKwPmm2Ds+VObKAQMEAQAAAAABASushgEAAAAAACJRIJj4FAjEAkR9IYcaA8B99f3Q/Ov7/wgh3Ph5WDzWUDL6AQMEAQAAAAAA', 'test message 1'),
        ('2f9a0c3b-8c4d-4f3a-9d2e-1b2c3d4e5f60', 'round-2', 'cHNidP8BAGYCAAAAAv6deG1s5w2msi0rziQ2HoNoxC2onFnWf6XLi36HIUWbAAAAAAAAAAAA9PRZ58PC4lJAJ7VEYtMMUC1E+poh/Gxo+0TNqvgh27wAAAAAAAAAAAABAAAAAAAAAAABagAAAAAAAQErAAAAAAAAAAAiUSC53+wMdwD72qU3mUE5FijgQ6Yt0XUhysD5ptg7PlTmygEDBAEAAAAAAQEr6AMAAAAAAAAiUSC53+wMdwD72qU3mUE5FijgQ6Yt0XUhysD5ptg7PlTmygEDBAEAAAAAAA==', 'test message 2');
    `)
	require.NoError(t, err, "failed to insert test intent rows")
}

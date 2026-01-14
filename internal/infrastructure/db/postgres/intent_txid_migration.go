package pgdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

//db *sql.DB

func BackfillIntentTxid(ctx context.Context, dbh *sql.DB) error {
	var tableExists int

	if err := dbh.QueryRowContext(ctx,
		existsQuery("intent", "txid"),
	).Scan(&tableExists); err != nil {
		return fmt.Errorf("failed to verify updated txid column existence in intent table: %w", err)
	}
	if tableExists > 0 {
		return nil
	}

	// make new intent table with txid column
	if err := ensureIntentNew(ctx, dbh); err != nil {
		return fmt.Errorf("failed to ensure txid column in intent table: %s", err)
	}

	// backfill existing intents with derived txids from proof
	if err := backfillIntent(context.Background(), dbh); err != nil {
		return fmt.Errorf("failed to backfill txids: %s", err)
	}

	// swap old intent table with new intent table that contains the new txid column
	if err := swapIntent(ctx, dbh); err != nil {
		return fmt.Errorf("failed to swap intent tables: %s", err)
	}

	// do we even need since we keep the intent id unchanged?
	if err := fixReceiverTableFK(ctx, dbh); err != nil {
		return fmt.Errorf("failed to fix receiver table foreign keys: %s", err)
	}
	// do we even need since we keep the intent id unchanged?
	if err := fixVtxoTableFK(ctx, dbh); err != nil {
		return fmt.Errorf("failed to fix vtxo table foreign keys: %s", err)
	}

	return nil

}

func ensureIntentNew(ctx context.Context, db *sql.DB) error {
	createIntentNew := `
		CREATE TABLE IF NOT EXISTS intent_new (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL,
    proof TEXT NOT NULL,
    message TEXT NOT NULL,
		txid TEXT UNIQUE NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);
	`

	if _, err := db.ExecContext(ctx, createIntentNew); err != nil {
		return fmt.Errorf("create intent_new: %w", err)
	}

	return nil
}

func backfillIntent(ctx context.Context, db *sql.DB) error {
	listIntent := `-- name: ListIntent :many
SELECT id, round_id, proof, message FROM intent
`
	insertIntent := `-- name: InsertIntent :exec
INSERT INTO intent_new (
   id, round_id, proof, message, txid
) VALUES (?, ?, ?, ?, ?)
`

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, listIntent) // SELECT ... FROM intent
	if err != nil {
		return err
	}
	defer rows.Close()

	stmt, err := tx.PrepareContext(ctx, insertIntent)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for rows.Next() {
		var (
			id, round_id, proof, message, txid string
		)
		if err = rows.Scan(&id, &round_id, &proof, &message); err != nil {
			return err
		}

		// derive the txid from the proof
		txid, err = deriveTxidFromProof(proof)
		if err != nil {
			return fmt.Errorf("derive txid from proof for intent id: %s: %w", id, err)
		}

		log.Debug(fmt.Sprintf("intent %s migrated -> txid %s", id, txid))

		if _, err = stmt.ExecContext(ctx,
			id, round_id, proof, message, txid,
		); err != nil {
			return err
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	err = tx.Commit()
	return err
}

func deriveTxidFromProof(proof string) (string, error) {
	tx, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return "", fmt.Errorf("psbt parse: %w", err)
	}
	return tx.UnsignedTx.TxID(), nil
}

func swapIntent(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Disable FKs for the swap window.
	if _, err = tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF;`); err != nil {
		return fmt.Errorf("pragma off: %w", err)
	}

	var oldCT, newCT int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM intent;`).Scan(&oldCT); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM intent_new;`).Scan(&newCT); err != nil {
		return err
	}
	if oldCT != newCT {
		return fmt.Errorf("backfill mismatch: intent=%d intent_new=%d", oldCT, newCT)
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE intent;`); err != nil {
		return err
	}

	if _, err = tx.ExecContext(ctx, `ALTER TABLE intent_new RENAME TO intent;`); err != nil {
		return err
	}

	// Re-enable FKs.
	if _, err = tx.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("pragma on: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func fixReceiverTableFK(ctx context.Context, db *sql.DB) error {
	const createNew = `CREATE TABLE IF NOT EXISTS receiver_new (
    intent_id TEXT NOT NULL,
    pubkey TEXT,
    onchain_address TEXT NOT NULL DEFAULT '',
    amount INTEGER NOT NULL,
    FOREIGN KEY (intent_id) REFERENCES intent(id),
    PRIMARY KEY (intent_id, pubkey, onchain_address)
	);`

	const copyData = `
	INSERT INTO receiver_new (
	  pubkey, onchain_address, amount, intent_id
	)
	SELECT
	  r.pubkey, r.onchain_address, r.amount, i.id AS intent_id
	FROM receiver AS r
	JOIN intent AS i
	  ON i.id = r.intent_id;`

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF;`); err != nil {
		return fmt.Errorf("disable fks: %w", err)
	}

	if _, err := tx.ExecContext(ctx, createNew); err != nil {
		return fmt.Errorf("create receiver_new: %w", err)
	}

	if _, err := tx.ExecContext(ctx, copyData); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DROP TABLE receiver;`); err != nil {
		return fmt.Errorf("drop old receiver: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE receiver_new RENAME TO receiver;`); err != nil {
		return fmt.Errorf("rename new->receiver: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("enable fks: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil

}

func fixVtxoTableFK(ctx context.Context, db *sql.DB) error {
	const createNew = `CREATE TABLE IF NOT EXISTS vtxo_new (
		txid TEXT NOT NULL,
		vout INTEGER NOT NULL,
		pubkey TEXT NOT NULL,
		amount INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		commitment_txid TEXT NOT NULL,
		spent_by TEXT,
		spent BOOLEAN NOT NULL DEFAULT FALSE,
		unrolled BOOLEAN NOT NULL DEFAULT FALSE,
		swept BOOLEAN NOT NULL DEFAULT FALSE,
		preconfirmed BOOLEAN NOT NULL DEFAULT FALSE,
		settled_by TEXT,
		ark_txid TEXT,
		intent_id TEXT,
		PRIMARY KEY (txid, vout),
		FOREIGN KEY (intent_id) REFERENCES intent(id)
	);`

	const copyData = `
	INSERT INTO vtxo_new (
	  txid, vout, pubkey, amount, expires_at, created_at, commitment_txid, spent_by, spent, unrolled, swept, preconfirmed, settled_by, ark_txid, intent_id
	)
	SELECT
	  v.txid, v.vout, v.pubkey, v.amount, v.expires_at, v.created_at, v.commitment_txid, v.spent_by, v.spent, v.unrolled, v.swept, v.preconfirmed, v.settled_by, v.ark_txid,
	  i.id AS intent_id
	FROM vtxo AS v
	JOIN intent AS i
	  ON i.id = v.intent_id;`

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF;`); err != nil {
		return fmt.Errorf("disable fks: %w", err)
	}

	if _, err := tx.ExecContext(ctx, createNew); err != nil {
		return fmt.Errorf("create vtxo_new: %w", err)
	}

	if _, err := tx.ExecContext(ctx, copyData); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DROP TABLE vtxo;`); err != nil {
		return fmt.Errorf("drop old vtxo: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE vtxo_new RENAME TO vtxo;`); err != nil {
		return fmt.Errorf("rename new->vtxo: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("enable fks: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil

}

func existsQuery(tableName, columnName string) string {
	return fmt.Sprintf(`
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name   = '%s'
          AND column_name  = '%s'
    `, tableName, columnName)
}

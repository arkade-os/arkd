package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

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

	// Add nullable column in-place (SQLite supports this)
	if _, err := dbh.ExecContext(ctx, `ALTER TABLE intent ADD COLUMN txid TEXT;`); err != nil {
		return fmt.Errorf("failed to add txid column: %w", err)
	}

	// backfill existing intents with derived txids from proof (in-place UPDATE)
	if err := backfillIntent(ctx, dbh); err != nil {
		return fmt.Errorf("failed to backfill txids: %s", err)
	}

	// create index on intent txid column
	if err := createIntentTxidIndex(ctx, dbh); err != nil {
		return fmt.Errorf("failed to create intent txid index: %s", err)
	}

	return nil
}

func backfillIntent(ctx context.Context, db *sql.DB) error {
	const listIntent = `SELECT id, proof FROM intent;`
	const updateIntent = `UPDATE intent SET txid = ? WHERE id = ?;`

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, listIntent)
	if err != nil {
		return err
	}
	// nolint:errcheck
	defer rows.Close()

	stmt, err := tx.PrepareContext(ctx, updateIntent)
	if err != nil {
		return err
	}
	// nolint:errcheck
	defer stmt.Close()

	for rows.Next() {
		var id, proof string
		if err = rows.Scan(&id, &proof); err != nil {
			return err
		}

		txid, derr := deriveTxidFromProof(proof)
		if derr != nil {
			return fmt.Errorf("derive txid from proof for intent id %s: %w", id, derr)
		}

		if _, err = stmt.ExecContext(ctx, txid, id); err != nil {
			return err
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return tx.Commit()
}

func deriveTxidFromProof(proof string) (string, error) {
	tx, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return "", fmt.Errorf("psbt parse: %w", err)
	}
	return tx.UnsignedTx.TxID(), nil
}

func createIntentTxidIndex(ctx context.Context, db *sql.DB) error {
	const createIndex = `
		CREATE INDEX IF NOT EXISTS idx_intent_txid ON intent(txid);`
	_, err := db.ExecContext(ctx, createIndex)
	if err != nil {
		return fmt.Errorf("create intent txid index: %w", err)
	}
	return nil
}

func existsQuery(tableName, columnName string) string {
	return fmt.Sprintf(
		`SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = '%s'`,
		tableName,
		columnName,
	)
}

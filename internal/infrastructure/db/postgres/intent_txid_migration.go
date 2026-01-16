package pgdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

func BackfillIntentTxid(ctx context.Context, dbh *sql.DB) error {
	exists, err := columnExists(ctx, dbh, "intent", "txid")
	if err != nil {
		return fmt.Errorf("failed to check intent.txid existence: %w", err)
	}
	if !exists {
		return nil
	}
	// Backfill existing intents with derived txids from proof (in-place UPDATE)
	if err := backfillIntent(ctx, dbh); err != nil {
		return fmt.Errorf("failed to backfill txids: %w", err)
	}
	// Create index on intent.txid to enable fast lookups
	if err := createIntentTxidIndex(ctx, dbh); err != nil {
		return fmt.Errorf("failed to create intent txid index: %w", err)
	}
	return nil
}

func backfillIntent(ctx context.Context, db *sql.DB) error {
	const listIntent = `SELECT id, proof FROM intent;`
	const updateIntent = `UPDATE intent SET txid = $1 WHERE id = $2;`

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx err: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, listIntent)
	if err != nil {
		return fmt.Errorf("query intents: %w", err)
	}

	type item struct {
		id    string
		proof string
	}
	var list []item

	for rows.Next() {
		var id, proof string
		if err = rows.Scan(&id, &proof); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan intent row: %w", err)
		}
		list = append(list, item{id: id, proof: proof})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate rows: %w", err)
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("close rows: %w", err)
	}

	for _, it := range list {
		txid, derr := deriveTxidFromProof(it.proof)
		if derr != nil {
			return fmt.Errorf("derive txid from proof for intent id %s: %w", it.id, derr)
		}
		if _, err = tx.ExecContext(ctx, updateIntent, txid, it.id); err != nil {
			return fmt.Errorf("update intent txid for id %s: %w", it.id, err)
		}
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
	const createIndex = `CREATE INDEX IF NOT EXISTS idx_intent_txid ON intent(txid);`
	_, err := db.ExecContext(ctx, createIndex)
	if err != nil {
		return fmt.Errorf("create intent txid index: %w", err)
	}
	return nil
}

// columnExists checks whether a column exists on a table using PRAGMA table_info.
func columnExists(ctx context.Context, db *sql.DB, tableName, columnName string) (bool, error) {
	const q = `
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name   = $1
              AND column_name  = $2
        );
    `
	var exists bool
	if err := db.QueryRowContext(ctx, q, tableName, columnName).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	_ "modernc.org/sqlite"
)

const (
	driverName = "sqlite"
	maxRetries = 5
)

func OpenDb(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory: %v", err)
		}
	}

	db, err := sql.Open(driverName, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	db.SetMaxOpenConns(1) // prevent concurrent writes

	return db, nil
}

func extendArray[T any](arr []T, position int) []T {
	if arr == nil {
		return make([]T, position+1)
	}

	if len(arr) <= position {
		return append(arr, make([]T, position-len(arr)+1)...)
	}

	return arr
}

func execTx(
	ctx context.Context, db *sql.DB, txBody func(*queries.Queries) error,
) error {
	var lastErr error
	for range maxRetries {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		qtx := queries.New(db).WithTx(tx)

		if err := txBody(qtx); err != nil {
			//nolint:all
			tx.Rollback()

			if isConflictError(err) {
				lastErr = err
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			if isConflictError(err) {
				lastErr = err
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	}

	return lastErr
}

func isConflictError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "database is locked") ||
		strings.Contains(errMsg, "database table is locked") ||
		strings.Contains(errMsg, "unique constraint failed") ||
		strings.Contains(errMsg, "foreign key constraint failed") ||
		strings.Contains(errMsg, "busy") ||
		strings.Contains(errMsg, "locked")
}

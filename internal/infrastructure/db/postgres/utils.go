package pgdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	_ "github.com/lib/pq"
)

const (
	driverName = "postgres"
	maxRetries = 5
)

func OpenDb(dsn string) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres db: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres db: %v", err)
	}

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

func parseCommitments(commitments, separator []byte) []string {
	if len(commitments) == 0 {
		return nil
	}
	parts := bytes.Split(commitments, separator)
	commitmentsStr := make([]string, 0, len(parts))
	for _, p := range parts {
		commitmentsStr = append(commitmentsStr, string(p))
	}
	return commitmentsStr
}

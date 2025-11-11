package pgdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

const (
	driverName = "postgres"
	maxRetries = 5
)

// OpenDb opens a connection with the DB.
// If the operation fails when trying to establish a connection and the `autoCreate` flag is set to
// true, OpenDb will try to create the database set in the DSN.
func OpenDb(dsn string, autoCreate bool) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres db: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := connectDB(ctx, db, dsn, autoCreate); err != nil {
		return nil, fmt.Errorf("unable to establish connection with db: %v", err)
	}

	return db, nil
}

// connectDB will try to `PingContext` to make sure we have established our connection as sql.Open
// is lazy and it only validates the arguments without creating a connection.
// Errors are forwarded as-is unless it's a DB does not exist error, in that case we try to create
// such database and try to connectDB again.
func connectDB(ctx context.Context, db *sql.DB, dsn string, autoCreate bool) error {
	if err := db.PingContext(ctx); err != nil {
		var dbErr *pq.Error
		// 3D000: invalid_catalog_name. This means that the selected db does not exist.
		if errors.As(err, &dbErr) && dbErr.Code == "3D000" && autoCreate {
			log.Info("Postgres database does not exist, creating it...")

			if err = createDB(ctx, dsn); err != nil {
				return err
			}

			// Recursively call pingDB now that the DB exists but set autoCreate false to avoid
			// unlikely but possible infinite recursion.
			return connectDB(ctx, db, dsn, false)
		}

		return err
	}

	return nil
}

// createDB tries to create a DB using the dsn to determine the db name.
func createDB(ctx context.Context, dsn string) error {
	// Extract the dbname only if the dsn is in URL format.
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		// TODO: implement this using PostgreSQL-style DSN (user=name dbname=db).
		return fmt.Errorf("cannot auto-create database unless the DSN uses URL format")
	}

	parsedURL, err := url.Parse(dsn)
	if err != nil {
		return err
	}

	// Now we need to connect to the DB without specifying the DB name so we keep a reference before
	// removing it from DSN.
	dbName := strings.TrimPrefix(parsedURL.Path, "/")
	if dbName == "" {
		return fmt.Errorf("cannot auto-create when database name is empty")
	}

	// Clear the path to connect to the default db.
	parsedURL.Path = ""

	// Encode the new URL (without the DB name) and connect as we need a new connection to create
	// the DB.
	rootDSN := parsedURL.String()
	rootDB, err := sql.Open(driverName, rootDSN)
	if err != nil {
		return err
	}
	defer rootDB.Close()

	query := "CREATE DATABASE " + dbName
	log.Infof("Executing query '%s'", query)
	if _, err := rootDB.ExecContext(ctx, query); err != nil {
		return err
	}

	return nil
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

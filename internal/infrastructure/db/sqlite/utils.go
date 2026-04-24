package sqlitedb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	log "github.com/sirupsen/logrus"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	driverName = "sqlite"
	maxRetries = 5
)

type SQLiteDB interface {
	Read() *sql.DB
	Write() *sql.DB
	Close() error
}

type sqliteDB struct {
	readDB  *sql.DB
	writeDB *sql.DB
}

func (s *sqliteDB) Read() *sql.DB {
	return s.readDB
}

func (s *sqliteDB) Write() *sql.DB {
	return s.writeDB
}

func (s *sqliteDB) Close() error {
	readErr := s.readDB.Close()
	writeErr := s.writeDB.Close()
	return errors.Join(readErr, writeErr)
}

// OpenDb returns a split SQLite handle with separate read and write pools.
//
// The read pool allows concurrent reads, while the write pool stays pinned to a
// single connection. WAL mode is enabled so reads do not block writes.
func OpenDb(dbPath string) (SQLiteDB, error) {
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory: %v", err)
		}
	}

	// Multi-connection read pool
	readDB, err := sql.Open(driverName, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open read db: %w", err)
	}
	readDB.SetMaxOpenConns(runtime.NumCPU())

	// single connection writer pool
	writeDB, err := sql.Open(driverName, dbPath)
	if err != nil {
		_ = readDB.Close()
		return nil, fmt.Errorf("failed to open write db: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	// Use WAL so reads do not block writes
	if _, err := writeDB.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		_ = readDB.Close()
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	// Use busy_timeout so reads/writes wait for WAL checkpointing instead of failing
	if _, err := writeDB.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		_ = readDB.Close()
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	if _, err := readDB.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		_ = readDB.Close()
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	// Check there are no errors when opening a connection
	if err := writeDB.Ping(); err != nil {
		_ = readDB.Close()
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to ping write db: %w", err)
	}

	if err := readDB.Ping(); err != nil {
		_ = readDB.Close()
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to ping read db: %w", err)
	}

	return &sqliteDB{
		readDB:  readDB,
		writeDB: writeDB,
	}, nil
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

// execTx runs txBody on a pinned write connection.
//
// The connection is kept for the full transaction so SQLite interrupt/cancel
// state stays scoped to that connection. Conflict-like errors are retried, and
// interrupted connections are discarded instead of being returned to the pool.
func execTx(
	ctx context.Context, db *sql.DB, txBody func(*queries.Queries) error,
) error {
	var lastErr error
	for range maxRetries {
		conn, err := db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("failed to acquire connection: %w", err)
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			_ = closeConn(conn, isInterruptError(ctx, err))
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		qtx := queries.New(conn).WithTx(tx)

		if err := txBody(qtx); err != nil {
			//nolint:all
			tx.Rollback()

			if closeErr := closeConn(conn, isInterruptError(ctx, err)); closeErr != nil {
				return closeErr
			}

			if isConflictError(err) {
				lastErr = err
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			if closeErr := closeConn(conn, isInterruptError(ctx, err)); closeErr != nil {
				return closeErr
			}
			if isConflictError(err) {
				lastErr = err
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		if err := closeConn(conn, false); err != nil {
			log.WithError(err).Warn("failed to close connection after successful commit")
		}
		return nil
	}

	return lastErr
}

// withReadQuerier runs fn on a pinned read connection.
//
// If the read is canceled or interrupted, the connection is discarded so later
// callers do not reuse a tainted SQLite connection from the pool.
func withReadQuerier(
	ctx context.Context, db SQLiteDB, fn func(*queries.Queries) error,
) error {
	conn, err := db.Read().Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}

	err = fn(queries.New(conn))
	if closeErr := closeConn(conn, isInterruptError(ctx, err)); closeErr != nil {
		if err != nil {
			return fmt.Errorf("%w: %w", err, closeErr)
		}
		return closeErr
	}

	return err
}

// withWriteQuerier runs fn on a pinned write connection.
//
// Even non-transactional writes go through an explicit connection so interrupt
// handling can discard the connection when SQLite reports it as tainted.
func withWriteQuerier(
	ctx context.Context, db SQLiteDB, fn func(*queries.Queries) error,
) error {
	conn, err := db.Write().Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}

	err = fn(queries.New(conn))
	if closeErr := closeConn(conn, isInterruptError(ctx, err)); closeErr != nil {
		if err != nil {
			return fmt.Errorf("%w: %w", err, closeErr)
		}
		return closeErr
	}

	return err
}

// closeConn closes conn and optionally forces the sql pool to discard it.
//
// When discard is true we surface driver.ErrBadConn through Raw so database/sql
// treats the underlying SQLite connection as unusable and does not recycle it.
func closeConn(conn *sql.Conn, discard bool) error {
	if conn == nil {
		return nil
	}

	if discard {
		err := conn.Raw(func(any) error {
			return driver.ErrBadConn
		})
		if errors.Is(err, driver.ErrBadConn) {
			err = nil
		}
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("failed to discard tainted connection: %w", err)
		}
	}

	if err := conn.Close(); err != nil {
		if discard && errors.Is(err, sql.ErrConnDone) {
			return nil
		}
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

// isInterruptError reports whether err is a context cancellation or a SQLite
// interrupt.
func isInterruptError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	if ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return true
	}

	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		code := sqliteErr.Code()
		return code == sqlite3.SQLITE_INTERRUPT || code&0xff == sqlite3.SQLITE_INTERRUPT
	}

	return false
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

func validateTimeRange(after, before int64) error {
	if after < 0 || before < 0 {
		return fmt.Errorf("after and before must be greater than or equal to 0")
	}
	if before > 0 && after > 0 && before <= after {
		return fmt.Errorf("before must be greater than after")
	}
	return nil
}

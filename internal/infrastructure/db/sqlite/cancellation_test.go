package sqlitedb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const slowRecursiveQuery = `
	WITH RECURSIVE cnt(x) AS (
		SELECT 1
		UNION ALL
		SELECT x + 1 FROM cnt WHERE x < 100000000
	)
	SELECT x FROM cnt
`

func TestCanceledReadQueryDiscardsConnection(t *testing.T) {
	// Use a shared in-memory DB because the test exercises a pinned read
	// connection while the DB wrapper exposes separate read/write pools.
	db, err := OpenDb("file::memory:?cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
	})

	ctx := t.Context()
	// Pin a single read connection so the test can verify that an interrupted
	// SQLite connection is discarded instead of being reused.
	conn, err := db.Read().Conn(ctx)
	require.NoError(t, err)

	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runSlowReadQuery(queryCtx, conn)
	}()

	err = <-errCh
	require.Error(t, err)
	require.True(t, isInterruptError(queryCtx, err), "expected interrupt-like error, got %v", err)
	// Discard the interrupted connection explicitly; a normal close would return
	// it to the pool for reuse.
	require.NoError(t, closeConn(conn, true))

	assertReadPoolStillHealthy(t, db, ctx)
}

func runSlowReadQuery(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, slowRecursiveQuery)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var value int
		if err := rows.Scan(&value); err != nil {
			return err
		}
	}

	return rows.Err()
}

func assertReadPoolStillHealthy(t *testing.T, db SQLiteDB, ctx context.Context) {
	t.Helper()

	for range 20 {
		var got int
		err := db.Read().QueryRowContext(ctx, `SELECT 1`).Scan(&got)
		require.NoError(t, err)
		require.Equal(t, 1, got)
	}
}

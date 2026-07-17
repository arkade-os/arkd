// Command migrate-sqlite-to-pg copies an arkd SQLite data-store dump into a
// Postgres data store.
//
// It is a one-off operational tool for moving a node from the sqlite backend to
// the postgres backend. It does NOT touch the event store (that has no sqlite
// backend and lives in badger/postgres separately).
//
// Flow:
//  1. (default) migrate the target Postgres schema to the SAME migration version
//     as the dump, using arkd's own postgres migration files. Do NOT migrate to
//     head here: if the dump predates a migration that transforms data (e.g.
//     add_vtxo_marker_dag), copying into a head schema would mismatch. Bring the
//     schema to the dump's version, copy 1:1, and let arkd apply the remaining
//     migrations itself on its next boot.
//  2. copy every base table (views and schema_migrations excluded) in FK order,
//     converting SQLite TEXT-JSON to JSONB and 0/1 integers to booleans.
//  3. reset SERIAL sequences to MAX(id).
//  4. verify per-table row counts match the source.
//
// Usage:
//
//	go run ./cmd/migrate-sqlite-to-pg \
//	  --sqlite ./arkd-v7-volume-sqlite-backup-20260717-124535.db \
//	  --pg 'postgres://user:pass@host:5432/arkd?sslmode=disable'
//
// Run from the arkd repo root so the default --migrations-dir resolves, or pass
// an absolute --migrations-dir.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

// tablesInFKOrder lists the base tables to copy, parents before children, so
// inserts satisfy foreign keys even without disabling FK triggers. Views (*_vw),
// schema_migrations (owned by golang-migrate) and sqlite_sequence are excluded.
var tablesInFKOrder = []string{
	"round",
	"intent",
	"intent_fees",
	"receiver",
	"tx",
	"vtxo",
	"vtxo_commitment_txid",
	"offchain_tx",
	"checkpoint_tx",
	"asset",
	"asset_projection",
	"asset_metadata_update",
	"conviction",
	"scheduled_session",
	"settings",
}

func main() {
	var (
		sqlitePath    = flag.String("sqlite", "", "path to the SQLite dump file (required)")
		pgDSN         = flag.String("pg", "", "target Postgres DSN in URL form, e.g. postgres://user:pass@host:5432/db?sslmode=disable (required)")
		migrationsDir = flag.String("migrations-dir", "internal/infrastructure/db/postgres/migration", "path to arkd's postgres migration files")
		targetVersion = flag.String("target-version", "20260615120126", "migrate the target schema to this migration version (must match the dump's version); empty to skip")
		pgAutocreate  = flag.Bool("pg-autocreate", false, "create the target database if it does not exist (DSN must be URL form)")
		skipMigrate   = flag.Bool("skip-migrate", false, "assume the target schema already exists at the correct version; skip the migrate step")
		verifyOnly    = flag.Bool("verify-only", false, "only compare row counts between source and target; copy nothing")
		batch         = flag.Int("batch", 1000, "max rows per multi-row INSERT")
	)
	flag.Parse()

	if *sqlitePath == "" || *pgDSN == "" {
		flag.Usage()
		log.Fatal("both --sqlite and --pg are required")
	}
	if err := run(*sqlitePath, *pgDSN, *migrationsDir, *targetVersion, *batch, *pgAutocreate, *skipMigrate, *verifyOnly); err != nil {
		log.Fatal(err)
	}
}

func run(sqlitePath, pgDSN, migrationsDir, targetVersion string, batch int, autocreate, skipMigrate, verifyOnly bool) error {
	ctx := context.Background()

	src, err := openSQLiteReadOnly(sqlitePath)
	if err != nil {
		return fmt.Errorf("open sqlite dump: %w", err)
	}
	defer src.Close()

	// Open (and, with --pg-autocreate, create) the target database first: the
	// migrate step below opens its own connection and would fail if the database
	// does not exist yet.
	pg, err := pgdb.OpenDb(pgDSN, autocreate)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer pg.Close()

	if !verifyOnly && !skipMigrate && targetVersion != "" {
		if err := migrateSchema(migrationsDir, targetVersion, pgDSN); err != nil {
			return fmt.Errorf("migrate target schema: %w", err)
		}
	}

	if verifyOnly {
		return verify(ctx, src, pg)
	}

	if err := copyAll(ctx, src, pg, batch); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	log.Info("verifying row counts")
	if err := verify(ctx, src, pg); err != nil {
		return err
	}

	log.Info("done. next: point arkd at this Postgres (ARKD_DB_TYPE=postgres, ARKD_PG_DB_URL=...) and boot it to apply the remaining migrations")
	return nil
}

// openSQLiteReadOnly opens the dump in read-only, immutable mode so nothing is
// written back to it (no -wal/-shm side files, no modification of the backup).
func openSQLiteReadOnly(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1&_pragma=busy_timeout(5000)", abs)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// migrateSchema brings the target Postgres to exactly targetVersion using arkd's
// own postgres migration files. Migrating to a specific version (not head) is
// deliberate: the dump must match the schema we copy into.
func migrateSchema(migrationsDir, targetVersion, pgDSN string) error {
	v, err := strconv.ParseUint(targetVersion, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid --target-version %q: %w", targetVersion, err)
	}
	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absDir); err != nil {
		return fmt.Errorf("migrations dir %q: %w", absDir, err)
	}
	sourceURL := "file://" + absDir

	m, err := migrate.New(sourceURL, pgDSN)
	if err != nil {
		return fmt.Errorf("init migrate: %w", err)
	}
	defer m.Close()

	log.Infof("migrating target schema to version %d", v)
	if err := m.Migrate(uint(v)); err != nil && err != migrate.ErrNoChange {
		return err
	}
	cur, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if dirty {
		return fmt.Errorf("target schema is dirty at version %d; resolve manually before copying", cur)
	}
	if cur != uint(v) {
		return fmt.Errorf("target schema at version %d, expected %d", cur, v)
	}
	log.Infof("target schema at version %d", cur)
	return nil
}

func copyAll(ctx context.Context, src, pg *sql.DB, batch int) error {
	conn, err := pg.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Best-effort: disable FK triggers for the load. Requires table-owner/superuser;
	// if it fails we continue, relying on the FK-ordered table list instead.
	if _, err := tx.ExecContext(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		log.WithError(err).Warn("could not set session_replication_role = replica; relying on FK-ordered inserts")
	}

	for _, table := range tablesInFKOrder {
		exists, err := tableExists(ctx, tx, table)
		if err != nil {
			return err
		}
		if !exists {
			// The dump can come from an arkd build whose schema differs slightly
			// from the target (e.g. a table the target arkd version doesn't
			// define). Skip rather than fail; the target arkd will never read it.
			log.Warnf("skipping %s: not present in target Postgres schema (data not migrated)", table)
			continue
		}
		n, err := copyTable(ctx, src, tx, table, batch)
		if err != nil {
			return fmt.Errorf("copy %s: %w", table, err)
		}
		log.Infof("copied %-24s %d rows", table, n)
	}

	if err := resetSequences(ctx, tx); err != nil {
		return fmt.Errorf("reset sequences: %w", err)
	}

	return tx.Commit()
}

// copyTable copies one table from src into the pg transaction. Columns are the
// intersection of the SQLite and Postgres schemas, so it adapts if the two drift
// slightly. Booleans (0/1) and JSONB (TEXT holding JSON) are converted per the
// Postgres column type.
func copyTable(ctx context.Context, src *sql.DB, tx *sql.Tx, table string, batch int) (int, error) {
	srcCols, err := sqliteColumns(src, table)
	if err != nil {
		return 0, err
	}
	tgtTypes, err := pgColumnTypes(ctx, tx, table)
	if err != nil {
		return 0, err
	}

	cols := make([]string, 0, len(srcCols))
	for _, c := range srcCols {
		if _, ok := tgtTypes[c]; ok {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return 0, fmt.Errorf("no shared columns between sqlite and postgres for %s", table)
	}

	selectSQL := fmt.Sprintf("SELECT %s FROM %s", joinIdents(cols), quoteIdent(table))
	rows, err := src.QueryContext(ctx, selectSQL)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	// Keep statements under Postgres' 65535 bound-parameter limit.
	effBatch := batch
	if max := 60000 / len(cols); max < effBatch {
		effBatch = max
	}
	if effBatch < 1 {
		effBatch = 1
	}

	buf := make([][]any, 0, effBatch)
	total := 0
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		if err := insertBatch(ctx, tx, table, cols, tgtTypes, buf); err != nil {
			return err
		}
		total += len(buf)
		buf = buf[:0]
		return nil
	}

	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return 0, err
		}
		for i, c := range cols {
			vals[i] = convert(vals[i], tgtTypes[c])
		}
		buf = append(buf, vals)
		if len(buf) >= effBatch {
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := flush(); err != nil {
		return 0, err
	}
	return total, nil
}

// convert normalises a SQLite driver value for a Postgres column:
//   - []byte -> string
//   - 0/1 integers -> bool for boolean columns
//   - NULL -> "" for NOT NULL text columns. SQLite allows NULL in a PRIMARY KEY
//     (e.g. receiver.pubkey for onchain-only receivers) whereas Postgres makes PK
//     columns NOT NULL; arkd itself stores the absent value as "" on Postgres, so
//     we mirror that.
func convert(v any, col colInfo) any {
	if b, ok := v.([]byte); ok {
		v = string(b)
	}
	if v == nil && col.NotNull && isTextType(col.DataType) {
		return ""
	}
	if col.DataType == "boolean" {
		switch tv := v.(type) {
		case int64:
			return tv != 0
		case string:
			return tv == "1" || strings.EqualFold(tv, "true")
		}
	}
	return v
}

func isTextType(dataType string) bool {
	switch dataType {
	case "text", "character varying", "character", "citext":
		return true
	}
	return false
}

func insertBatch(ctx context.Context, tx *sql.Tx, table string, cols []string, tgtTypes map[string]colInfo, rows [][]any) error {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(quoteIdent(table))
	b.WriteString(" (")
	b.WriteString(joinIdents(cols))
	b.WriteString(") VALUES ")

	args := make([]any, 0, len(rows)*len(cols))
	p := 1
	for r, row := range rows {
		if r > 0 {
			b.WriteString(",")
		}
		b.WriteString("(")
		for c, col := range cols {
			if c > 0 {
				b.WriteString(",")
			}
			b.WriteString("$")
			b.WriteString(strconv.Itoa(p))
			if tgtTypes[col].DataType == "jsonb" {
				b.WriteString("::jsonb")
			}
			args = append(args, row[c])
			p++
		}
		b.WriteString(")")
	}
	// DO NOTHING collapses the duplicate rows that SQLite retains because it
	// treats NULLs as distinct in a PRIMARY KEY (see convert). It also makes the
	// copy idempotent if re-run.
	b.WriteString(" ON CONFLICT DO NOTHING")

	_, err := tx.ExecContext(ctx, b.String(), args...)
	return err
}

// resetSequences sets each SERIAL sequence to MAX(id) so future inserts don't
// collide with copied ids. pg_get_serial_sequence returns NULL for non-serial
// columns, which we skip.
func resetSequences(ctx context.Context, tx *sql.Tx) error {
	for _, table := range tablesInFKOrder {
		exists, err := tableExists(ctx, tx, table)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		tgtTypes, err := pgColumnTypes(ctx, tx, table)
		if err != nil {
			return err
		}
		if _, ok := tgtTypes["id"]; !ok {
			continue
		}
		var seq sql.NullString
		if err := tx.QueryRowContext(ctx, "SELECT pg_get_serial_sequence($1, 'id')", table).Scan(&seq); err != nil {
			return err
		}
		if !seq.Valid {
			continue
		}
		q := fmt.Sprintf("SELECT setval($1, (SELECT COALESCE(MAX(id), 1) FROM %s))", quoteIdent(table))
		if _, err := tx.ExecContext(ctx, q, seq.String); err != nil {
			return err
		}
		log.Infof("reset sequence for %s", table)
	}
	return nil
}

// verify compares the Postgres row count to the number of DISTINCT primary-key
// rows in SQLite. Using the distinct-PK count (rather than the raw count) means
// the check accounts for rows SQLite retains but Postgres collapses on its PK
// (see convert / insertBatch) without a false mismatch. Text PK columns are
// COALESCEd to ” to mirror the NULL -> "" coercion.
func verify(ctx context.Context, src, pg *sql.DB) error {
	mismatch := false
	log.Infof("%-24s %14s %12s", "table", "sqlite(distinct)", "postgres")
	for _, table := range tablesInFKOrder {
		exists, err := tableExists(ctx, pg, table)
		if err != nil {
			return err
		}
		if !exists {
			log.Warnf("%-24s %14s %12s  <-- skipped (absent in target)", table, "-", "-")
			continue
		}
		expected, err := expectedCount(ctx, src, table)
		if err != nil {
			return fmt.Errorf("expected count sqlite %s: %w", table, err)
		}
		pgN, err := countRows(ctx, pg, table)
		if err != nil {
			return fmt.Errorf("count postgres %s: %w", table, err)
		}
		flag := ""
		if expected != pgN {
			flag = "  <-- MISMATCH"
			mismatch = true
		}
		log.Infof("%-24s %14d %12d%s", table, expected, pgN, flag)
	}
	if mismatch {
		return fmt.Errorf("row-count mismatch between sqlite and postgres")
	}
	return nil
}

// expectedCount returns the number of rows Postgres should hold for a table: the
// count of DISTINCT primary-key tuples in SQLite (text PK columns COALESCEd to
// ”), or the raw count when the table has no primary key.
func expectedCount(ctx context.Context, src *sql.DB, table string) (int64, error) {
	pk, err := sqlitePKColumns(src, table)
	if err != nil {
		return 0, err
	}
	if len(pk) == 0 {
		return countRows(ctx, src, table)
	}
	exprs := make([]string, len(pk))
	for i, c := range pk {
		exprs[i] = fmt.Sprintf("COALESCE(%s, '')", quoteIdent(c))
	}
	q := fmt.Sprintf("SELECT COUNT(*) FROM (SELECT DISTINCT %s FROM %s)",
		strings.Join(exprs, ", "), quoteIdent(table))
	var n int64
	err = src.QueryRowContext(ctx, q).Scan(&n)
	return n, err
}

// sqlitePKColumns returns the primary-key column names of a SQLite table,
// ordered by their position in the key.
func sqlitePKColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

func countRows(ctx context.Context, db *sql.DB, table string) (int64, error) {
	var n int64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(table)).Scan(&n)
	return n, err
}

func sqliteColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// colInfo describes a target Postgres column.
type colInfo struct {
	DataType string
	NotNull  bool
}

func pgColumnTypes(ctx context.Context, tx *sql.Tx, table string) (map[string]colInfo, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1",
		table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	types := make(map[string]colInfo)
	for rows.Next() {
		var name, dtype, nullable string
		if err := rows.Scan(&name, &dtype, &nullable); err != nil {
			return nil, err
		}
		types[name] = colInfo{DataType: dtype, NotNull: nullable == "NO"}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("table %q not found in target Postgres (is the schema migrated?)", table)
	}
	return types, nil
}

// rowQueryer is satisfied by both *sql.DB and *sql.Tx.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func tableExists(ctx context.Context, q rowQueryer, table string) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)",
		table).Scan(&exists)
	return exists, err
}

func quoteIdent(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

func joinIdents(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = quoteIdent(id)
	}
	return strings.Join(q, ", ")
}

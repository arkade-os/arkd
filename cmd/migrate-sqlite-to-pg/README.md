# migrate-sqlite-to-pg

One-off operational tool to migrate an arkd **data store** from the SQLite
backend to Postgres.

## Scope

Migrates the SQL projection tables only. It does **not** touch the event store —
arkd's source of truth. The event store has no SQLite backend (it lives in badger
or Postgres) and is not present in a SQLite dump, so it stays where it is. If you
need a Postgres-only deployment, migrating the event log is a separate exercise.

## How it works

1. **Migrate the target Postgres schema to the dump's *matching* migration
   version** (default `20260615120126`), using arkd's own postgres migration
   files via the golang-migrate library — **not** to head.
2. **Copy every base table** (views and `schema_migrations` excluded) in
   foreign-key order, converting types (see below), with `ON CONFLICT DO NOTHING`.
3. **Reset `SERIAL` sequences** to `MAX(id)`.
4. **Verify** each table's Postgres row count against the number of distinct
   primary-key rows in SQLite.

After it finishes, point arkd at the Postgres database and boot it: arkd applies
any remaining migrations itself (e.g. `add_vtxo_marker_dag`, which backfills the
marker DAG, migrates `swept`, and drops the column).

## Why "matching version", not head

arkd's SQL tables are projections and some migrations transform data in place. A
dump is a snapshot at whatever version the node was running. If you migrated the
target to head first and then copied, the schemas would not line up (columns
added/dropped by the intervening migration). Bringing the target to the dump's
exact version means the copy is a clean 1:1, and arkd's normal boot-time migration
then carries the data forward the same way it would for any existing node.

## Prerequisites

- Go toolchain. Run from the arkd repo root so the default `--migrations-dir`
  resolves (or pass an absolute `--migrations-dir`).
- A target Postgres reachable via a **URL-form** DSN
  (`postgres://user:pass@host:5432/db?sslmode=disable`).
- A consistent SQLite dump — ideally taken with the node stopped, so the dump and
  the (separate) event store represent the same point in time.

## Usage

```bash
go run ./cmd/migrate-sqlite-to-pg \
  --sqlite /path/to/arkd-sqlite-backup.db \
  --pg 'postgres://user:pass@host:5432/arkd?sslmode=disable'
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--sqlite` | (required) | Path to the SQLite dump file. Opened read-only/immutable. |
| `--pg` | (required) | Target Postgres DSN, URL form. |
| `--migrations-dir` | `internal/infrastructure/db/postgres/migration` | arkd's postgres migration files. |
| `--target-version` | `20260615120126` | Migrate the target schema to this version. Must match the dump's version. Empty to skip. |
| `--pg-autocreate` | `false` | Create the target database if it does not exist (DSN must be URL form). |
| `--skip-migrate` | `false` | Assume the schema already exists at the correct version. |
| `--verify-only` | `false` | Only compare row counts; copy nothing. |
| `--batch` | `1000` | Max rows per multi-row INSERT (auto-capped to stay under Postgres' parameter limit). |

## Runbook

1. Provision an empty target Postgres (e.g. a new Dokploy Postgres service).
2. Run the tool against a **throwaway** target first and confirm the verification
   table shows matching counts.
3. Repeat against the real target.
4. Point arkd at it — `ARKD_DB_TYPE=postgres`, `ARKD_PG_DB_URL=<dsn>`, leave the
   event store config unchanged — and boot arkd to apply the remaining migrations.

## Type handling

- `TEXT` holding JSON (e.g. `tx.children`) → cast to `JSONB`.
- `0`/`1` integers → `BOOLEAN`.
- `NULL` → `''` for `NOT NULL` text columns. SQLite allows `NULL` in a primary key
  (e.g. `receiver.pubkey` for onchain-only receivers) whereas Postgres makes PK
  columns `NOT NULL`; arkd itself stores the absent value as `''`, so we mirror it.

## Notes and caveats

- **Row counts can legitimately shrink.** SQLite treats `NULL` as distinct in a
  primary key, so it can retain duplicate rows that Postgres collapses once the
  `NULL`s become `''`. With `ON CONFLICT DO NOTHING` those rows collapse, matching
  what a native arkd-on-Postgres node would hold. Verification accounts for this by
  comparing against the SQLite distinct-primary-key count, not the raw count.
- **Tables absent from the target schema are skipped** (with a warning) rather than
  failing the run. A dump can come from an arkd build whose schema differs slightly
  from the target; the target arkd will never read a table it doesn't define.
- **FK handling.** Inserts run in foreign-key dependency order. The tool also
  attempts `SET LOCAL session_replication_role = replica` (needs table-owner /
  superuser) as a belt-and-suspenders measure; if that fails it logs a warning and
  relies on the ordering alone.
- **Idempotent.** The whole copy runs in one transaction and uses
  `ON CONFLICT DO NOTHING`, so a re-run against a partially-populated target is safe.

## Verifying independently

```bash
go run ./cmd/migrate-sqlite-to-pg --sqlite <dump> --pg <dsn> --verify-only
```

package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/infrastructure/db/markerbackfill"
)

// backfillDoneMarkerID is the sentinel latch marker inserted after a successful
// backfill so shallow-DAG installs (no boundary markers) still skip re-runs.
const backfillDoneMarkerID = "__vtxo_markers_backfill_done__"

// BackfillVtxoMarkers rebuilds the vtxo marker DAG (real BFS depths + boundary
// markers) in a single transaction. It preserves swept status by copying every
// currently-swept outpoint into swept_vtxo before clearing and rebuilding the
// markers, and verifies the swept count is unchanged (before == after) else
// rolls back the whole thing. The data guard makes it idempotent: a completed
// run is a no-op, an interrupted (rolled-back) run re-runs.
func BackfillVtxoMarkers(ctx context.Context, dbh *sql.DB) (err error) {
	var colCount int
	if err = dbh.QueryRowContext(ctx, existsQuery("vtxo", "markers")).Scan(&colCount); err != nil {
		return fmt.Errorf("check vtxo.markers existence: %w", err)
	}
	if colCount <= 0 {
		return nil
	}

	tx, err := dbh.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// (a) DATA-GUARD: already backfilled if real topology or latch marker exists.
	var done bool
	if err = tx.QueryRowContext(ctx, `
		SELECT
			EXISTS(SELECT 1 FROM marker WHERE parent_markers IS NOT NULL AND parent_markers <> '[]')
			OR EXISTS(SELECT 1 FROM marker WHERE id = ?)
	`, backfillDoneMarkerID).Scan(&done); err != nil {
		return fmt.Errorf("data guard check: %w", err)
	}
	if done {
		return tx.Commit()
	}

	// (b) snapshot swept count (before).
	var sweptBefore int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vtxo_vw WHERE swept = 1`,
	).Scan(&sweptBefore); err != nil {
		return fmt.Errorf("count swept before: %w", err)
	}

	// (c) preserve swept status via swept_vtxo (immune to marker reassignment).
	// OR IGNORE preserves any pre-existing swept_vtxo.swept_at.
	if _, err = tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO swept_vtxo (txid, vout, swept_at)
		SELECT v.txid, v.vout, strftime('%s','now') * 1000
		FROM vtxo v
		WHERE EXISTS (
			SELECT 1 FROM swept_marker sm
			JOIN json_each(v.markers) j ON j.value = sm.marker_id
		)
	`); err != nil {
		return fmt.Errorf("preserve swept into swept_vtxo: %w", err)
	}

	// (d) clear marker topology (swept_marker first: FK to marker.id).
	if _, err = tx.ExecContext(ctx, `DELETE FROM swept_marker`); err != nil {
		return fmt.Errorf("clear swept_marker: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM marker`); err != nil {
		return fmt.Errorf("clear marker: %w", err)
	}

	// (e) load, compute, write.
	all, err := loadVtxoRows(ctx, tx)
	if err != nil {
		return fmt.Errorf("load vtxos: %w", err)
	}
	vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(all)
	depthByTxid, _ := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)
	// Required deviation from cmd tool: pin unreachable txids at depth 0 so they
	// get self-markers minted and never dangle at a deleted marker id.
	for txid := range vtxosByTxid {
		if _, ok := depthByTxid[txid]; !ok {
			depthByTxid[txid] = 0
		}
	}
	markersByOutpoint, newMarkers := markerbackfill.ComputeMarkers(
		vtxosByTxid, parentsByChildTxid, depthByTxid,
	)

	// bulk-insert markers via prepared per-row statement.
	insMarker, err := tx.PrepareContext(ctx,
		`INSERT INTO marker (id, depth, parent_markers) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare marker insert: %w", err)
	}
	for _, m := range newMarkers {
		if _, err = insMarker.ExecContext(ctx, m.ID, int64(m.Depth),
			markerbackfill.JSONStringArray(m.ParentMarkers)); err != nil {
			_ = insMarker.Close()
			return fmt.Errorf("insert marker %s: %w", m.ID, err)
		}
	}
	if err = insMarker.Close(); err != nil {
		return fmt.Errorf("close marker insert: %w", err)
	}

	// sentinel latch marker.
	if _, err = tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO marker (id, depth, parent_markers) VALUES (?, 0, '[]')`,
		backfillDoneMarkerID,
	); err != nil {
		return fmt.Errorf("insert latch marker: %w", err)
	}

	// update vtxo depth + markers (plain TEXT, no cast).
	updVtxo, err := tx.PrepareContext(ctx,
		`UPDATE vtxo SET depth = ?, markers = ? WHERE txid = ? AND vout = ?`)
	if err != nil {
		return fmt.Errorf("prepare vtxo update: %w", err)
	}
	for _, v := range all {
		d := depthByTxid[v.Txid]
		if _, err = updVtxo.ExecContext(ctx, int64(d),
			markerbackfill.JSONStringArray(markersByOutpoint[v.Outpoint()]),
			v.Txid, int64(v.Vout),
		); err != nil {
			_ = updVtxo.Close()
			return fmt.Errorf("update vtxo %s: %w", v.Outpoint(), err)
		}
	}
	if err = updVtxo.Close(); err != nil {
		return fmt.Errorf("close vtxo update: %w", err)
	}

	// (f) verify swept count unchanged.
	var sweptAfter int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vtxo_vw WHERE swept = 1`,
	).Scan(&sweptAfter); err != nil {
		return fmt.Errorf("count swept after: %w", err)
	}
	if sweptAfter != sweptBefore {
		err = fmt.Errorf(
			"swept count changed during backfill (before=%d after=%d); aborting",
			sweptBefore, sweptAfter,
		)
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func loadVtxoRows(ctx context.Context, tx *sql.Tx) ([]markerbackfill.VtxoRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT txid, vout, ark_txid FROM vtxo`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []markerbackfill.VtxoRow
	for rows.Next() {
		var v markerbackfill.VtxoRow
		var ark sql.NullString
		if err := rows.Scan(&v.Txid, &v.Vout, &ark); err != nil {
			return nil, err
		}
		v.ArkTxid, v.ArkTxidValid = ark.String, ark.Valid
		out = append(out, v)
	}
	return out, rows.Err()
}

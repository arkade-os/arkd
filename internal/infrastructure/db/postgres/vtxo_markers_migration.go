package pgdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/infrastructure/db/markerbackfill"
	"github.com/lib/pq"
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
	// Pre-guard: schema must have the marker feature.
	exists, err := columnExists(ctx, dbh, "vtxo", "markers")
	if err != nil {
		return fmt.Errorf("failed to check vtxo.markers existence: %w", err)
	}
	if !exists {
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
			EXISTS(SELECT 1 FROM marker WHERE parent_markers IS NOT NULL AND parent_markers <> '[]'::jsonb)
			OR EXISTS(SELECT 1 FROM marker WHERE id = $1)
	`, backfillDoneMarkerID).Scan(&done); err != nil {
		return fmt.Errorf("data guard check: %w", err)
	}
	if done {
		return tx.Commit() // no-op, idempotent skip
	}

	// (b) snapshot swept count (before).
	var sweptBefore int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vtxo_vw WHERE swept = true`,
	).Scan(&sweptBefore); err != nil {
		return fmt.Errorf("count swept before: %w", err)
	}

	// (c) preserve swept status: copy swept-by-marker outpoints into swept_vtxo.
	// swept_vtxo is keyed by (txid,vout) and immune to marker reassignment.
	// ON CONFLICT DO NOTHING preserves any pre-existing swept_vtxo.swept_at.
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO swept_vtxo (txid, vout, swept_at)
		SELECT v.txid, v.vout, (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
		FROM vtxo v
		WHERE EXISTS (
			SELECT 1 FROM swept_marker sm
			WHERE v.markers @> jsonb_build_array(sm.marker_id)
		)
		ON CONFLICT (txid, vout) DO NOTHING
	`); err != nil {
		return fmt.Errorf("preserve swept into swept_vtxo: %w", err)
	}

	// (d) clear marker topology (swept_marker first: FK swept_marker.marker_id -> marker.id).
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

	// bulk-insert new markers via COPY.
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("marker", "id", "depth", "parent_markers"))
	if err != nil {
		return fmt.Errorf("prepare copy: %w", err)
	}
	for _, m := range newMarkers {
		if _, err = stmt.ExecContext(ctx, m.ID, int32(m.Depth),
			markerbackfill.JSONStringArray(m.ParentMarkers)); err != nil {
			_ = stmt.Close()
			return fmt.Errorf("copy marker: %w", err)
		}
	}
	if _, err = stmt.ExecContext(ctx); err != nil {
		_ = stmt.Close()
		return fmt.Errorf("copy flush: %w", err)
	}
	if err = stmt.Close(); err != nil {
		return fmt.Errorf("copy close: %w", err)
	}

	// sentinel latch marker so shallow-DAG installs (no boundary markers) still latch.
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO marker (id, depth, parent_markers) VALUES ($1, 0, '[]'::jsonb)
		ON CONFLICT (id) DO NOTHING
	`, backfillDoneMarkerID); err != nil {
		return fmt.Errorf("insert latch marker: %w", err)
	}

	// batch-update vtxo depth + markers (unreachable pinned to depth 0 above).
	if err = updateVtxosPG(ctx, tx, all, depthByTxid, markersByOutpoint); err != nil {
		return fmt.Errorf("update vtxos: %w", err)
	}

	// (f) verify swept count unchanged.
	var sweptAfter int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vtxo_vw WHERE swept = true`,
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

func updateVtxosPG(
	ctx context.Context, tx *sql.Tx,
	all []markerbackfill.VtxoRow,
	depthByTxid map[string]uint32,
	markersByOutpoint map[string][]string,
) error {
	type upd struct {
		txid    string
		vout    uint32
		depth   uint32
		markers []string
	}
	updates := make([]upd, 0, len(all))
	for _, v := range all {
		d := depthByTxid[v.Txid] // always present (unreachable pinned to 0)
		updates = append(updates, upd{v.Txid, v.Vout, d, markersByOutpoint[v.Outpoint()]})
	}
	const batchSize = 1000
	for i := 0; i < len(updates); i += batchSize {
		end := i + batchSize
		if end > len(updates) {
			end = len(updates)
		}
		batch := updates[i:end]
		var sb strings.Builder
		sb.WriteString(`UPDATE vtxo SET depth = v.depth, markers = v.markers::jsonb FROM (VALUES `)
		args := make([]any, 0, len(batch)*4)
		for j, u := range batch {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := j*4 + 1
			fmt.Fprintf(&sb, "($%d::text,$%d::integer,$%d::integer,$%d::text)", b, b+1, b+2, b+3)
			args = append(args, u.txid, int32(u.vout), int32(u.depth),
				markerbackfill.JSONStringArray(u.markers))
		}
		sb.WriteString(
			`) AS v(txid, vout, depth, markers) WHERE vtxo.txid = v.txid AND vtxo.vout = v.vout`,
		)
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("update batch at %d: %w", i, err)
		}
	}
	return nil
}

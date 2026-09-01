package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/infrastructure/db/markerbackfill"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

// backfillDoneMarkerID is the sentinel latch marker written LAST after a
// successful backfill. Identical value to the sqlite/postgres constant so the
// semantics match across stores. It lets shallow DAGs (no boundary markers)
// and interrupted runs be detected on re-run.
const backfillDoneMarkerID = "__vtxo_markers_backfill_done__"

// BackfillVtxoMarkers rebuilds the vtxo marker DAG (real BFS depths + boundary
// markers) for a badger data store, reusing the shared markerbackfill compute.
//
// Unlike the SQL backfill it does NO swept preservation: badger tracks swept as
// vtxoDTO.Swept keyed by outpoint, which is never written here, so swept status
// is preserved by construction. It also does NOT run in a single transaction:
// badger txns have a size limit (ErrTxnTooBig), so writes are per-record (each
// its own txn, matching the repo's existing idioms). The operation is therefore
// NOT atomic, so the completion latch (written strictly last) is the SOLE
// "fully completed" signal; it makes the backfill idempotent and self-healing.
func BackfillVtxoMarkers(
	ctx context.Context,
	vtxoStore *badgerhold.Store,
	markerStore *badgerhold.Store,
) (err error) {
	// (a) COMPLETION-LATCH data guard: skip only if the latch exists.
	//
	// The latch is written last (step f), so its presence proves the whole run
	// finished. Unlike the SQL sibling we deliberately do NOT also treat existing
	// topology as "done": the rebuild is non-atomic and writes boundary markers
	// (real topology) in step (d) BEFORE the latch, so a crash mid-run can leave
	// topology present with no latch. Gating on the latch alone means such an
	// interrupted store is re-detected as unfinished; step (d) clear-then-rebuilds
	// from scratch, so re-running converges to the correct full rebuild. In badger
	// the backfill runs at DB init before the app serves traffic, so the first
	// successful run always writes the latch before any live topology is minted;
	// "topology present, latch absent" therefore only ever means an interrupted
	// run, which must rebuild rather than short-circuit.
	var latch markerDTO
	latchErr := markerStore.Get(backfillDoneMarkerID, &latch)
	if latchErr != nil && !errors.Is(latchErr, badgerhold.ErrNotFound) {
		return fmt.Errorf("data guard: get latch: %w", latchErr)
	}
	if latchErr == nil {
		return nil // latch present -> already backfilled -> no-op
	}

	// (b) load all vtxos.
	var dtos []vtxoDTO
	if err = vtxoStore.Find(&dtos, &badgerhold.Query{}); err != nil {
		return fmt.Errorf("load vtxos: %w", err)
	}
	all := make([]markerbackfill.VtxoRow, 0, len(dtos))
	for i := range dtos {
		d := &dtos[i]
		all = append(all, markerbackfill.VtxoRow{
			Txid:         d.Txid,
			Vout:         d.VOut,
			ArkTxid:      d.ArkTxid,
			ArkTxidValid: d.ArkTxid != "",
		})
	}

	// (c) compute depths + markers (pure, in-memory; reuses markerbackfill).
	vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(all)
	depthByTxid, _ := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)
	// Required deviation: pin unreachable txids at depth 0 so they get
	// self-markers minted and never dangle at a deleted marker id (same as sql).
	for txid := range vtxosByTxid {
		if _, ok := depthByTxid[txid]; !ok {
			depthByTxid[txid] = 0
		}
	}
	markersByOutpoint, newMarkers := markerbackfill.ComputeMarkers(
		vtxosByTxid, parentsByChildTxid, depthByTxid,
	)

	// (d) rebuild the marker store: clear-then-rebuild. Clearing removes stale
	// legacy self-markers for now-interior vtxos (upsert-only would leak them);
	// the deterministic ids make the rebuild idempotent on re-run.
	if err = clearMarkers(markerStore); err != nil {
		return fmt.Errorf("clear markers: %w", err)
	}
	for _, m := range newMarkers {
		dto := markerDTO{ID: m.ID, Depth: m.Depth, ParentMarkerIDs: m.ParentMarkers}
		if err = upsertMarkerWithRetry(markerStore, m.ID, dto); err != nil {
			return fmt.Errorf("upsert marker %s: %w", m.ID, err)
		}
	}

	// (e) write Depth + MarkerIDs for every vtxo. Read-modify-write on the loaded
	// DTO so Swept and every other field are preserved by construction; only
	// Depth/MarkerIDs are mutated. UpdatedAt is deliberately left untouched to
	// match the SQL backfill (which sets only depth+markers): stamping every
	// vtxo at migration time would pollute the UpdatedAt-range queries
	// (GetPendingSpentVtxosWithPubKeys, GetVtxoPubKeysByCommitmentTxids). Written
	// after markers so an interrupted run re-does both.
	for i := range dtos {
		d := dtos[i]
		op := d.Outpoint.String()
		d.Depth = depthByTxid[d.Txid]
		d.MarkerIDs = markersByOutpoint[op]
		if err = updateVtxoWithRetry(vtxoStore, op, d); err != nil {
			return fmt.Errorf("update vtxo %s: %w", op, err)
		}
	}

	// (f) write the completion latch LAST. Its presence is what the guard checks.
	latchDTO := markerDTO{ID: backfillDoneMarkerID, Depth: 0, ParentMarkerIDs: nil}
	if err = upsertMarkerWithRetry(markerStore, backfillDoneMarkerID, latchDTO); err != nil {
		return fmt.Errorf("write completion latch: %w", err)
	}
	return nil
}

// clearMarkers deletes every marker record via per-record deletes so the clear
// cannot hit ErrTxnTooBig on a large marker table (the per-record idiom used
// throughout the badger package). The marker set is bounded well below the vtxo
// count, so a single scan to collect ids is fine.
func clearMarkers(markerStore *badgerhold.Store) error {
	var dtos []markerDTO
	if err := markerStore.Find(&dtos, &badgerhold.Query{}); err != nil {
		return err
	}
	for _, d := range dtos {
		if err := markerStore.Delete(d.ID, markerDTO{}); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

func upsertMarkerWithRetry(s *badgerhold.Store, key string, dto markerDTO) error {
	err := s.Upsert(key, dto)
	for attempts := 1; errors.Is(err, badger.ErrConflict) && attempts <= maxRetries; attempts++ {
		time.Sleep(100 * time.Millisecond)
		err = s.Upsert(key, dto)
	}
	return err
}

func updateVtxoWithRetry(s *badgerhold.Store, key string, dto vtxoDTO) error {
	err := s.Update(key, dto)
	for attempts := 1; errors.Is(err, badger.ErrConflict) && attempts <= maxRetries; attempts++ {
		time.Sleep(100 * time.Millisecond)
		err = s.Update(key, dto)
	}
	return err
}

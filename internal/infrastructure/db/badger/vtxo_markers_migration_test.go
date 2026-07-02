package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
	"github.com/timshannon/badgerhold/v4"
)

func newStores(t *testing.T) (vtxo, marker *badgerhold.Store) {
	t.Helper()
	v, err := createDB("", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })
	m, err := createDB("", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	return v, m
}

func chainTxid(prefix string, k int) string { return fmt.Sprintf("%s%04d", prefix, k) }

func opOf(txid string) string { return fmt.Sprintf("%s:0", txid) }

// seedLegacyVtxo inserts a pre-DAG vtxo (Depth=0, self-marker only) plus its
// bare self-marker record, exactly what a legacy badger install carries.
func seedLegacyVtxo(t *testing.T, vs, ms *badgerhold.Store, txid, arkTxid string, swept bool) {
	t.Helper()
	op := opOf(txid)
	dto := vtxoDTO{
		Vtxo: domain.Vtxo{
			Outpoint:  domain.Outpoint{Txid: txid, VOut: 0},
			ArkTxid:   arkTxid,
			Depth:     0,
			MarkerIDs: []string{op},
			Swept:     swept,
			Amount:    1000,
			PubKey:    "pk_" + txid,
		},
	}
	require.NoError(t, vs.Insert(op, dto))
	require.NoError(t, ms.Insert(op, markerDTO{ID: op, Depth: 0, ParentMarkerIDs: nil}))
}

func seedLegacyChain(t *testing.T, vs, ms *badgerhold.Store, prefix string, length int, swept bool) {
	t.Helper()
	for k := 0; k < length; k++ {
		var arkTxid string
		if k < length-1 {
			arkTxid = chainTxid(prefix, k+1)
		}
		seedLegacyVtxo(t, vs, ms, chainTxid(prefix, k), arkTxid, swept)
	}
}

func getVtxo(t *testing.T, vs *badgerhold.Store, op string) vtxoDTO {
	t.Helper()
	var dto vtxoDTO
	require.NoError(t, vs.Get(op, &dto))
	return dto
}

func getMarker(t *testing.T, ms *badgerhold.Store, id string) (markerDTO, bool) {
	t.Helper()
	var dto markerDTO
	err := ms.Get(id, &dto)
	if errors.Is(err, badgerhold.ErrNotFound) {
		return markerDTO{}, false
	}
	require.NoError(t, err)
	return dto, true
}

type vtxoSnap struct {
	op        string
	depth     uint32
	markerIDs []string
}

type markerSnap struct {
	id      string
	depth   uint32
	parents []string
}

func snapshotVtxos(t *testing.T, vs *badgerhold.Store) []vtxoSnap {
	t.Helper()
	var dtos []vtxoDTO
	require.NoError(t, vs.Find(&dtos, &badgerhold.Query{}))
	out := make([]vtxoSnap, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, vtxoSnap{d.Outpoint.String(), d.Depth, d.MarkerIDs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].op < out[j].op })
	return out
}

func snapshotMarkers(t *testing.T, ms *badgerhold.Store) []markerSnap {
	t.Helper()
	var dtos []markerDTO
	require.NoError(t, ms.Find(&dtos, &badgerhold.Query{}))
	out := make([]markerSnap, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, markerSnap{d.ID, d.Depth, d.ParentMarkerIDs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// (a) legacy chain -> correct BFS depths + boundary markers, both stores rewritten.
func TestBackfillLegacyChain(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyChain(t, vs, ms, "main", 206, false)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))

	for k := 0; k < 206; k++ {
		v := getVtxo(t, vs, opOf(chainTxid("main", k)))
		require.Equalf(t, uint32(k), v.Depth, "depth for main%04d", k)
	}

	root, ok := getMarker(t, ms, opOf(chainTxid("main", 0)))
	require.True(t, ok)
	require.Empty(t, root.ParentMarkerIDs)

	m100, ok := getMarker(t, ms, "main0100:marker:100")
	require.True(t, ok)
	require.Equal(t, []string{opOf(chainTxid("main", 0))}, m100.ParentMarkerIDs)

	m200, ok := getMarker(t, ms, "main0200:marker:200")
	require.True(t, ok)
	require.Equal(t, []string{"main0100:marker:100"}, m200.ParentMarkerIDs)

	require.Equal(t,
		[]string{opOf(chainTxid("main", 0))},
		getVtxo(t, vs, opOf(chainTxid("main", 47))).MarkerIDs)
	require.Equal(t,
		[]string{"main0100:marker:100"},
		getVtxo(t, vs, opOf(chainTxid("main", 150))).MarkerIDs)

	_, ok = getMarker(t, ms, backfillDoneMarkerID)
	require.True(t, ok, "latch must be present")
}

// orphan sub-case: unreachable txid pinned to depth 0 with a valid self-marker.
func TestBackfillOrphanPinnedToZero(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyVtxo(t, vs, ms, "orph0", "prunedparent", false)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))

	v := getVtxo(t, vs, opOf("orph0"))
	require.Equal(t, uint32(0), v.Depth)
	require.NotEmpty(t, v.MarkerIDs)
	for _, id := range v.MarkerIDs {
		_, ok := getMarker(t, ms, id)
		require.Truef(t, ok, "marker %s referenced by orphan must exist", id)
	}
}

// (b) idempotent re-run is a no-op (latch).
func TestBackfillIdempotentReRun(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyChain(t, vs, ms, "main", 206, false)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))
	vBefore := snapshotVtxos(t, vs)
	mBefore := snapshotMarkers(t, ms)

	// guard tripwire: fresh legacy vtxo inserted after the first run must be
	// left untouched by the second run (guard short-circuits on the latch).
	seedLegacyVtxo(t, vs, ms, "trip0", "", false)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))

	trip := getVtxo(t, vs, opOf("trip0"))
	require.Equal(t, uint32(0), trip.Depth)
	require.Equal(t, []string{opOf("trip0")}, trip.MarkerIDs)

	// snapshots for the pre-existing set must be unchanged (ignore trip0).
	require.Equal(t, vBefore, filterOutOp(snapshotVtxos(t, vs), opOf("trip0")))
	require.Equal(t, mBefore, filterOutMarker(snapshotMarkers(t, ms), opOf("trip0")))
}

func filterOutOp(s []vtxoSnap, op string) []vtxoSnap {
	out := make([]vtxoSnap, 0, len(s))
	for _, v := range s {
		if v.op != op {
			out = append(out, v)
		}
	}
	return out
}

func filterOutMarker(s []markerSnap, id string) []markerSnap {
	out := make([]markerSnap, 0, len(s))
	for _, m := range s {
		if m.id != id {
			out = append(out, m)
		}
	}
	return out
}

// shallow DAG (< MarkerInterval) mints no boundary markers; only the latch
// proves "done", so the re-run must still be a no-op.
func TestBackfillShallowDAGLatch(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyChain(t, vs, ms, "sh", 3, false)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))
	vBefore := snapshotVtxos(t, vs)
	mBefore := snapshotMarkers(t, ms)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))
	require.Equal(t, vBefore, snapshotVtxos(t, vs))
	require.Equal(t, mBefore, snapshotMarkers(t, ms))
}

// (c1) topology present but NO latch is NOT treated as "done": on the non-atomic
// badger path that state can only mean an interrupted run, so the backfill must
// clear the stale topology and rebuild to a correct, latched state (self-heal).
func TestBackfillTopologyWithoutLatchRebuilds(t *testing.T) {
	vs, ms := newStores(t)
	// a vtxo carrying stale boundary-marker topology from a crashed prior run,
	// with no parent linkage (ArkTxid empty) so the correct rebuild depth is 0.
	dto := vtxoDTO{
		Vtxo: domain.Vtxo{
			Outpoint:  domain.Outpoint{Txid: "fresh0", VOut: 0},
			Depth:     150,
			MarkerIDs: []string{"fresh0:marker:100"},
		},
	}
	require.NoError(t, vs.Insert(opOf("fresh0"), dto))
	require.NoError(t, ms.Insert("root:0", markerDTO{ID: "root:0", Depth: 0}))
	require.NoError(t, ms.Insert("fresh0:marker:100",
		markerDTO{ID: "fresh0:marker:100", Depth: 100, ParentMarkerIDs: []string{"root:0"}}))

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))

	// the lone, unlinked vtxo is rebuilt to depth 0 with a fresh self-marker.
	v := getVtxo(t, vs, opOf("fresh0"))
	require.Equal(t, uint32(0), v.Depth)
	require.Equal(t, []string{opOf("fresh0")}, v.MarkerIDs)

	// stale topology markers were cleared; the self-marker and latch remain.
	_, ok := getMarker(t, ms, "fresh0:marker:100")
	require.False(t, ok, "stale boundary marker must be cleared")
	_, ok = getMarker(t, ms, "root:0")
	require.False(t, ok, "stale root marker must be cleared")
	_, ok = getMarker(t, ms, opOf("fresh0"))
	require.True(t, ok, "rebuilt self-marker must be present")
	_, ok = getMarker(t, ms, backfillDoneMarkerID)
	require.True(t, ok, "latch must be present after rebuild")
}

// (d) swept preserved: backfill must NOT touch Swept.
func TestBackfillSweptPreserved(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyChain(t, vs, ms, "swp", 3, true)
	seedLegacyChain(t, vs, ms, "uns", 2, false)

	sweptBefore := countSwept(t, vs)
	require.Equal(t, 3, sweptBefore)

	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))

	for k := 0; k < 3; k++ {
		require.True(t, getVtxo(t, vs, opOf(chainTxid("swp", k))).Swept)
	}
	for k := 0; k < 2; k++ {
		require.False(t, getVtxo(t, vs, opOf(chainTxid("uns", k))).Swept)
	}
	require.Equal(t, sweptBefore, countSwept(t, vs))
	// depth/markers were still rewritten on the swept chain.
	require.Equal(t, uint32(2), getVtxo(t, vs, opOf(chainTxid("swp", 2))).Depth)
}

func countSwept(t *testing.T, vs *badgerhold.Store) int {
	t.Helper()
	var dtos []vtxoDTO
	require.NoError(t, vs.Find(&dtos, &badgerhold.Query{}))
	n := 0
	for _, d := range dtos {
		if d.Swept {
			n++
		}
	}
	return n
}

// (e) interrupted-run / partial state: a crash left partial boundary markers
// (real topology) with NO latch. This exercises the genuine crash-then-restart
// path that startup wiring (service.go) runs: BackfillVtxoMarkers is called
// directly against the partial store, WITHOUT any manual clear. Because the
// latch is the sole completion signal, the run must self-heal, converging to
// exactly the state of a clean rebuild with the latch present.
func TestBackfillInterruptedRunRecovery(t *testing.T) {
	vs, ms := newStores(t)
	seedLegacyChain(t, vs, ms, "main", 206, false)
	// simulate a partial prior run: one boundary marker written, no latch. This
	// is the "topology present, latch absent" store that the old topology guard
	// would have short-circuited, permanently freezing the half-migrated state.
	require.NoError(t, ms.Upsert("main0100:marker:100",
		markerDTO{ID: "main0100:marker:100", Depth: 100, ParentMarkerIDs: []string{opOf("main0000")}}))

	// no manual clear: the backfill itself must detect the missing latch and
	// clear-then-rebuild from scratch.
	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))
	interrupted := snapshotVtxos(t, vs)
	interruptedMarkers := snapshotMarkers(t, ms)

	// the self-healed state must equal a clean rebuild on an identical legacy
	// chain that never saw a partial run.
	cleanVs, cleanMs := newStores(t)
	seedLegacyChain(t, cleanVs, cleanMs, "main", 206, false)
	require.NoError(t, BackfillVtxoMarkers(context.Background(), cleanVs, cleanMs))
	require.Equal(t, snapshotVtxos(t, cleanVs), interrupted)
	require.Equal(t, snapshotMarkers(t, cleanMs), interruptedMarkers)

	require.Equal(t, uint32(205), getVtxo(t, vs, opOf(chainTxid("main", 205))).Depth)
	_, ok := getMarker(t, ms, backfillDoneMarkerID)
	require.True(t, ok, "latch must be present after self-healing")
}

// empty store: no error; marker store ends with exactly the latch.
func TestBackfillEmptyStore(t *testing.T) {
	vs, ms := newStores(t)
	require.NoError(t, BackfillVtxoMarkers(context.Background(), vs, ms))
	markers := snapshotMarkers(t, ms)
	require.Len(t, markers, 1)
	require.Equal(t, backfillDoneMarkerID, markers[0].id)
}

// wiring test: real construction via the shared-store path and the accessor.
func TestBackfillWiringSharedStore(t *testing.T) {
	dir := t.TempDir()
	vtxoRepo, err := NewVtxoRepository(dir, nil)
	require.NoError(t, err)
	vr := vtxoRepo.(*VtxoRepository)
	markerRepo, err := NewMarkerRepository(dir, nil, vr.GetStore())
	require.NoError(t, err)
	defer markerRepo.Close()

	ctx := context.Background()
	vtxos := []domain.Vtxo{
		{
			Outpoint:  domain.Outpoint{Txid: "wire0000", VOut: 0},
			ArkTxid:   "wire0001",
			MarkerIDs: []string{opOf("wire0000")},
			Amount:    1000,
		},
		{
			Outpoint:  domain.Outpoint{Txid: "wire0001", VOut: 0},
			MarkerIDs: []string{opOf("wire0000")},
			Amount:    1000,
		},
	}
	require.NoError(t, vtxoRepo.AddVtxos(ctx, vtxos))
	require.NoError(t, markerRepo.CreateRootMarkersForVtxos(ctx, vtxos))

	acc := markerRepo.(MarkerStoreAccessor)
	require.NoError(t, BackfillVtxoMarkers(ctx, vr.GetStore(), acc.GetMarkerStore()))

	_, ok := getMarker(t, acc.GetMarkerStore(), backfillDoneMarkerID)
	require.True(t, ok)
	require.Equal(t, uint32(1), getVtxo(t, vr.GetStore(), opOf("wire0001")).Depth)

	// second run is a no-op.
	vBefore := snapshotVtxos(t, vr.GetStore())
	mBefore := snapshotMarkers(t, acc.GetMarkerStore())
	require.NoError(t, BackfillVtxoMarkers(ctx, vr.GetStore(), acc.GetMarkerStore()))
	require.Equal(t, vBefore, snapshotVtxos(t, vr.GetStore()))
	require.Equal(t, mBefore, snapshotMarkers(t, acc.GetMarkerStore()))
}

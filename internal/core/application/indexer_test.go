package application

import (
	"context"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for indexer tests

type mockVtxoRepoForIndexer struct {
	mock.Mock
}

func (m *mockVtxoRepoForIndexer) GetVtxos(
	ctx context.Context,
	outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	args := m.Called(ctx, outpoints)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Vtxo), args.Error(1)
}

// Stub implementations for unused VtxoRepository methods
func (m *mockVtxoRepoForIndexer) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	return nil
}

func (m *mockVtxoRepoForIndexer) SettleVtxos(
	ctx context.Context,
	spentVtxos map[domain.Outpoint]string,
	commitmentTxid string,
) error {
	return nil
}

func (m *mockVtxoRepoForIndexer) SpendVtxos(
	ctx context.Context,
	spentVtxos map[domain.Outpoint]string,
	arkTxid string,
) error {
	return nil
}

func (m *mockVtxoRepoForIndexer) UnrollVtxos(
	ctx context.Context,
	outpoints []domain.Outpoint,
) error {
	return nil
}

func (m *mockVtxoRepoForIndexer) GetAllNonUnrolledVtxos(
	ctx context.Context,
	pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	return nil, nil, nil
}

func (m *mockVtxoRepoForIndexer) GetAllSweepableUnrolledVtxos(
	ctx context.Context,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockVtxoRepoForIndexer) GetAllVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetAllVtxosWithPubKeys(
	ctx context.Context,
	pubkeys []string,
	after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetExpiringLiquidity(
	ctx context.Context,
	after, before int64,
) (uint64, error) {
	return 0, nil
}
func (m *mockVtxoRepoForIndexer) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (m *mockVtxoRepoForIndexer) UpdateVtxosExpiration(
	ctx context.Context,
	outpoints []domain.Outpoint,
	expiresAt int64,
) error {
	return nil
}

func (m *mockVtxoRepoForIndexer) GetLeafVtxosForBatch(
	ctx context.Context,
	txid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
) ([]domain.Outpoint, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetAllChildrenVtxos(
	ctx context.Context,
	txid string,
) ([]domain.Outpoint, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetVtxoPubKeysByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
	withMinimumAmount uint64,
) ([]string, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetPendingSpentVtxosWithPubKeys(
	ctx context.Context,
	pubkeys []string,
	after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepoForIndexer) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockVtxoRepoForIndexer) Close() {}

type mockMarkerRepoForIndexer struct {
	mock.Mock
}

func (m *mockMarkerRepoForIndexer) GetMarker(
	ctx context.Context,
	id string,
) (*domain.Marker, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Marker), args.Error(1)
}

func (m *mockMarkerRepoForIndexer) GetVtxoChainByMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.Vtxo, error) {
	args := m.Called(ctx, markerIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Vtxo), args.Error(1)
}

// Stub implementations for unused MarkerRepository methods
func (m *mockMarkerRepoForIndexer) AddMarker(ctx context.Context, marker domain.Marker) error {
	return nil
}

func (m *mockMarkerRepoForIndexer) GetMarkersByDepth(
	ctx context.Context,
	depth uint32,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) GetMarkersByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) GetMarkersByIds(
	ctx context.Context,
	ids []string,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) SweepMarker(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) error {
	return nil
}

func (m *mockMarkerRepoForIndexer) BulkSweepMarkers(
	ctx context.Context,
	markerIDs []string,
	sweptAt int64,
) error {
	return nil
}

func (m *mockMarkerRepoForIndexer) SweepMarkerWithDescendants(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) (int64, error) {
	return 0, nil
}

func (m *mockMarkerRepoForIndexer) IsMarkerSwept(
	ctx context.Context,
	markerID string,
) (bool, error) {
	return false, nil
}

func (m *mockMarkerRepoForIndexer) GetSweptMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.SweptMarker, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) UpdateVtxoMarkers(
	ctx context.Context,
	outpoint domain.Outpoint,
	markerIDs []string,
) error {
	return nil
}

func (m *mockMarkerRepoForIndexer) GetVtxosByMarker(
	ctx context.Context,
	markerID string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) SweepVtxosByMarker(
	ctx context.Context,
	markerID string,
) (int64, error) {
	return 0, nil
}

func (m *mockMarkerRepoForIndexer) CreateRootMarkersForVtxos(
	ctx context.Context,
	vtxos []domain.Vtxo,
) error {
	return nil
}

func (m *mockMarkerRepoForIndexer) GetVtxosByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepoForIndexer) GetVtxosByArkTxid(
	ctx context.Context,
	arkTxid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockMarkerRepoForIndexer) Close() {}

type mockRepoManagerForIndexer struct {
	vtxos   *mockVtxoRepoForIndexer
	markers *mockMarkerRepoForIndexer
}

func (m *mockRepoManagerForIndexer) Events() domain.EventRepository { return nil }
func (m *mockRepoManagerForIndexer) Rounds() domain.RoundRepository { return nil }
func (m *mockRepoManagerForIndexer) Vtxos() domain.VtxoRepository   { return m.vtxos }
func (m *mockRepoManagerForIndexer) Markers() domain.MarkerRepository {
	// Must explicitly return nil to avoid Go's nil interface issue
	// where a nil concrete type wrapped in an interface != nil
	if m.markers == nil {
		return nil
	}
	return m.markers
}
func (m *mockRepoManagerForIndexer) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m *mockRepoManagerForIndexer) OffchainTxs() domain.OffchainTxRepository      { return nil }
func (m *mockRepoManagerForIndexer) Convictions() domain.ConvictionRepository      { return nil }
func (m *mockRepoManagerForIndexer) Assets() domain.AssetRepository                { return nil }
func (m *mockRepoManagerForIndexer) Fees() domain.FeeRepository                    { return nil }
func (m *mockRepoManagerForIndexer) Close()                                        {}

// newTestIndexer creates a fresh set of mock repos and an indexerService for testing.
func newTestIndexer() (
	*mockVtxoRepoForIndexer,
	*mockMarkerRepoForIndexer,
	*indexerService,
) {
	vtxoRepo := &mockVtxoRepoForIndexer{}
	markerRepo := &mockMarkerRepoForIndexer{}
	repoManager := &mockRepoManagerForIndexer{vtxos: vtxoRepo, markers: markerRepo}
	indexer := &indexerService{repoManager: repoManager}
	return vtxoRepo, markerRepo, indexer
}

// TestPrefetchVtxosByMarkers_BuildsCacheFromMarkerChain verifies that prefetchVtxosByMarkers
// correctly traverses the marker hierarchy (following ParentMarkerIDs) and bulk fetches
// all VTXOs associated with those markers into a cache map.
func TestPrefetchVtxosByMarkers_BuildsCacheFromMarkerChain(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "start-vtxo", VOut: 0}

	// Starting VTXO with markers at depth 200
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "start-vtxo", VOut: 0},
		MarkerIDs: []string{"marker-200"},
		Depth:     200,
	}

	// Marker chain: marker-200 -> marker-100 -> marker-0 (root)
	marker200 := &domain.Marker{
		ID:              "marker-200",
		Depth:           200,
		ParentMarkerIDs: []string{"marker-100"},
	}
	marker100 := &domain.Marker{ID: "marker-100", Depth: 100, ParentMarkerIDs: []string{"marker-0"}}
	marker0 := &domain.Marker{ID: "marker-0", Depth: 0, ParentMarkerIDs: []string{}}

	// VTXOs associated with all markers in the chain
	chainVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "vtxo-a", VOut: 0}, Depth: 50},
		{Outpoint: domain.Outpoint{Txid: "vtxo-b", VOut: 0}, Depth: 100},
		{Outpoint: domain.Outpoint{Txid: "vtxo-c", VOut: 0}, Depth: 150},
		{Outpoint: domain.Outpoint{Txid: "vtxo-d", VOut: 0}, Depth: 200},
	}

	// Setup expectations
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	markerRepo.On("GetMarker", ctx, "marker-200").Return(marker200, nil)
	markerRepo.On("GetMarker", ctx, "marker-100").Return(marker100, nil)
	markerRepo.On("GetMarker", ctx, "marker-0").Return(marker0, nil)

	// Expect bulk fetch with all markers in the chain
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		// Should contain marker-200, marker-100, marker-0
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		return len(ids) == 3 && idSet["marker-200"] && idSet["marker-100"] && idSet["marker-0"]
	})).Return(chainVtxos, nil)

	// Execute
	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Verify cache contains all VTXOs plus the start VTXO
	require.Len(t, cache, 5) // 4 chain VTXOs + 1 start VTXO
	require.Contains(t, cache, "start-vtxo:0")
	require.Contains(t, cache, "vtxo-a:0")
	require.Contains(t, cache, "vtxo-b:0")
	require.Contains(t, cache, "vtxo-c:0")
	require.Contains(t, cache, "vtxo-d:0")
}

// TestPrefetchVtxosByMarkers_EmptyMarkersReturnsStartVtxoOnly verifies that when the
// starting VTXO has no markers, the cache only contains the starting VTXO itself.
func TestPrefetchVtxosByMarkers_EmptyMarkersReturnsStartVtxoOnly(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "vtxo-no-markers", VOut: 0}

	// VTXO with no markers
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-no-markers", VOut: 0},
		MarkerIDs: []string{}, // Empty markers
		Depth:     0,
	}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Cache should only contain the start VTXO
	require.Len(t, cache, 1)
	require.Contains(t, cache, "vtxo-no-markers:0")

	// Marker repo should not be called for chain traversal
	markerRepo.AssertNotCalled(t, "GetMarker", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "GetVtxoChainByMarkers", mock.Anything, mock.Anything)
}

// TestPrefetchVtxosByMarkers_NilMarkerRepoReturnsEmptyCache verifies that when the
// marker repository is nil (not configured), an empty cache is returned gracefully.
func TestPrefetchVtxosByMarkers_NilMarkerRepoReturnsEmptyCache(t *testing.T) {
	vtxoRepo := &mockVtxoRepoForIndexer{}
	repoManager := &mockRepoManagerForIndexer{vtxos: vtxoRepo, markers: nil}

	indexer := &indexerService{repoManager: repoManager}

	ctx := context.Background()
	startKey := Outpoint{Txid: "vtxo-any", VOut: 0}

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Cache should be empty when marker repo is nil
	require.Empty(t, cache)

	// VTXO repo should not be called
	vtxoRepo.AssertNotCalled(t, "GetVtxos", mock.Anything, mock.Anything)
}

// TestGetVtxosFromCacheOrDB_CacheHitAvoidsDBCall verifies that when all requested
// outpoints are in the cache, no database call is made.
func TestGetVtxosFromCacheOrDB_CacheHitAvoidsDBCall(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()

	// Pre-populated cache
	cache := map[string]domain.Vtxo{
		"cached-vtxo-1:0": {
			Outpoint: domain.Outpoint{Txid: "cached-vtxo-1", VOut: 0},
			Amount:   1000,
		},
		"cached-vtxo-2:0": {
			Outpoint: domain.Outpoint{Txid: "cached-vtxo-2", VOut: 0},
			Amount:   2000,
		},
	}

	outpoints := []domain.Outpoint{
		{Txid: "cached-vtxo-1", VOut: 0},
		{Txid: "cached-vtxo-2", VOut: 0},
	}

	result, err := indexer.getVtxosFromCacheOrDB(ctx, outpoints, cache)

	require.NoError(t, err)
	require.Len(t, result, 2)

	// Verify GetVtxos was never called (all cache hits)
	vtxoRepo.AssertNotCalled(t, "GetVtxos", mock.Anything, mock.Anything)
}

// TestGetVtxosFromCacheOrDB_CacheMissTriggersDBCall verifies that when outpoints
// are not in the cache, a database call is made for the missing ones only.
func TestGetVtxosFromCacheOrDB_CacheMissTriggersDBCall(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()

	// Cache with one VTXO
	cache := map[string]domain.Vtxo{
		"cached-vtxo:0": {Outpoint: domain.Outpoint{Txid: "cached-vtxo", VOut: 0}, Amount: 1000},
	}

	// Request both cached and uncached
	outpoints := []domain.Outpoint{
		{Txid: "cached-vtxo", VOut: 0},
		{Txid: "uncached-vtxo", VOut: 0},
	}

	// DB should be called only for uncached outpoint
	dbVtxo := domain.Vtxo{Outpoint: domain.Outpoint{Txid: "uncached-vtxo", VOut: 0}, Amount: 3000}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "uncached-vtxo", VOut: 0}}).
		Return([]domain.Vtxo{dbVtxo}, nil)

	result, err := indexer.getVtxosFromCacheOrDB(ctx, outpoints, cache)

	require.NoError(t, err)
	require.Len(t, result, 2)

	// Verify the uncached VTXO was added to cache
	require.Contains(t, cache, "uncached-vtxo:0")
	require.Equal(t, uint64(3000), cache["uncached-vtxo:0"].Amount)

	vtxoRepo.AssertExpectations(t)
}

// TestGetVtxosFromCacheOrDB_AllCacheMiss verifies behavior when cache is empty
// and all outpoints must be fetched from the database.
func TestGetVtxosFromCacheOrDB_AllCacheMiss(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()

	// Empty cache
	cache := make(map[string]domain.Vtxo)

	outpoints := []domain.Outpoint{
		{Txid: "vtxo-1", VOut: 0},
		{Txid: "vtxo-2", VOut: 0},
		{Txid: "vtxo-3", VOut: 0},
	}

	dbVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "vtxo-1", VOut: 0}, Amount: 100},
		{Outpoint: domain.Outpoint{Txid: "vtxo-2", VOut: 0}, Amount: 200},
		{Outpoint: domain.Outpoint{Txid: "vtxo-3", VOut: 0}, Amount: 300},
	}

	vtxoRepo.On("GetVtxos", ctx, outpoints).Return(dbVtxos, nil)

	result, err := indexer.getVtxosFromCacheOrDB(ctx, outpoints, cache)

	require.NoError(t, err)
	require.Len(t, result, 3)

	// All VTXOs should now be in cache
	require.Len(t, cache, 3)
	require.Contains(t, cache, "vtxo-1:0")
	require.Contains(t, cache, "vtxo-2:0")
	require.Contains(t, cache, "vtxo-3:0")
}

// TestGetVtxosFromCacheOrDB_DBErrorPropagated verifies that database errors
// are properly propagated to the caller.
func TestGetVtxosFromCacheOrDB_DBErrorPropagated(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)

	outpoints := []domain.Outpoint{{Txid: "vtxo-err", VOut: 0}}

	vtxoRepo.On("GetVtxos", ctx, outpoints).
		Return(nil, fmt.Errorf("vtxo not found"))

	result, err := indexer.getVtxosFromCacheOrDB(ctx, outpoints, cache)

	require.Error(t, err)
	require.Nil(t, result)
}

// TestPrefetchVtxosByMarkers_HandlesMultipleParentMarkers verifies that the BFS
// traversal correctly handles VTXOs with multiple parent markers (diamond pattern
// in the marker DAG).
func TestPrefetchVtxosByMarkers_HandlesMultipleParentMarkers(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "diamond-vtxo", VOut: 0}

	// VTXO with multiple markers (diamond pattern)
	// marker-C has two parents: marker-A and marker-B, both pointing to marker-root
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "diamond-vtxo", VOut: 0},
		MarkerIDs: []string{"marker-C"},
		Depth:     200,
	}

	markerC := &domain.Marker{
		ID:              "marker-C",
		Depth:           200,
		ParentMarkerIDs: []string{"marker-A", "marker-B"},
	}
	markerA := &domain.Marker{ID: "marker-A", Depth: 100, ParentMarkerIDs: []string{"marker-root"}}
	markerB := &domain.Marker{ID: "marker-B", Depth: 100, ParentMarkerIDs: []string{"marker-root"}}
	markerRoot := &domain.Marker{ID: "marker-root", Depth: 0, ParentMarkerIDs: []string{}}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	markerRepo.On("GetMarker", ctx, "marker-C").Return(markerC, nil)
	markerRepo.On("GetMarker", ctx, "marker-A").Return(markerA, nil)
	markerRepo.On("GetMarker", ctx, "marker-B").Return(markerB, nil)
	markerRepo.On("GetMarker", ctx, "marker-root").Return(markerRoot, nil)

	chainVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "vtxo-from-chain", VOut: 0}},
	}

	// Should collect all 4 markers despite diamond pattern
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		// Must have all 4 markers, no duplicates
		return len(ids) == 4 &&
			idSet["marker-C"] &&
			idSet["marker-A"] &&
			idSet["marker-B"] &&
			idSet["marker-root"]
	})).Return(chainVtxos, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Verify we got the starting VTXO plus chain VTXOs
	require.Contains(t, cache, "diamond-vtxo:0")
	require.Contains(t, cache, "vtxo-from-chain:0")
}

// TestPrefetchVtxosByMarkers_GetVtxosError verifies that when GetVtxos fails
// to retrieve the starting VTXO, prefetchVtxosByMarkers returns an empty cache
// gracefully without panicking.
func TestPrefetchVtxosByMarkers_GetVtxosError(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "vtxo-error", VOut: 0}

	// Simulate DB error when fetching start VTXO
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return(nil, fmt.Errorf("database connection lost"))

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Cache should be empty on error
	require.Empty(t, cache)

	// Marker repo should not be called
	markerRepo.AssertNotCalled(t, "GetMarker", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "GetVtxoChainByMarkers", mock.Anything, mock.Anything)
}

// TestPrefetchVtxosByMarkers_GetMarkerError verifies that when GetMarker
// fails for a marker in the BFS traversal, the function still returns
// partial results from successfully fetched markers.
func TestPrefetchVtxosByMarkers_GetMarkerError(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "vtxo-partial", VOut: 0}

	// Starting VTXO with a marker at depth 200
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-partial", VOut: 0},
		MarkerIDs: []string{"marker-200"},
		Depth:     200,
	}

	// marker-200 has parent marker-100, but marker-100 lookup will fail
	marker200 := &domain.Marker{
		ID:              "marker-200",
		Depth:           200,
		ParentMarkerIDs: []string{"marker-100"},
	}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	markerRepo.On("GetMarker", ctx, "marker-200").Return(marker200, nil)
	// marker-100 lookup fails
	markerRepo.On("GetMarker", ctx, "marker-100").
		Return(nil, fmt.Errorf("marker not found"))

	// GetVtxoChainByMarkers should still be called with the markers we did collect
	chainVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "vtxo-from-200", VOut: 0}, Depth: 180},
	}
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		// Should have marker-200 and marker-100 (both were added to markerIDs)
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		return len(ids) == 2 && idSet["marker-200"] && idSet["marker-100"]
	})).Return(chainVtxos, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Should have the start VTXO plus chain VTXOs from marker-200
	require.Contains(t, cache, "vtxo-partial:0")
	require.Contains(t, cache, "vtxo-from-200:0")
}

// TestPrefetchVtxosByMarkers_GetVtxoChainByMarkersError verifies that when
// the bulk fetch of VTXOs by markers fails, the cache still contains at
// least the starting VTXO.
func TestPrefetchVtxosByMarkers_GetVtxoChainByMarkersError(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "vtxo-bulk-err", VOut: 0}

	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-bulk-err", VOut: 0},
		MarkerIDs: []string{"marker-100"},
		Depth:     100,
	}

	marker100 := &domain.Marker{
		ID:              "marker-100",
		Depth:           100,
		ParentMarkerIDs: []string{},
	}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	markerRepo.On("GetMarker", ctx, "marker-100").Return(marker100, nil)

	// Bulk fetch fails
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.Anything).
		Return(nil, fmt.Errorf("bulk fetch failed"))

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Cache should still contain the start VTXO
	require.Len(t, cache, 1)
	require.Contains(t, cache, "vtxo-bulk-err:0")
}

// TestPrefetchVtxosByMarkers_DeepChainManyMarkers verifies that BFS traversal
// correctly handles a deep chain with 5+ markers (depth 500), collecting all
// markers without off-by-one errors or missed parents.
func TestPrefetchVtxosByMarkers_DeepChainManyMarkers(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "deep-vtxo", VOut: 0}

	// VTXO at depth 500 with marker at depth 500
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "deep-vtxo", VOut: 0},
		MarkerIDs: []string{"marker-500"},
		Depth:     500,
	}

	// Linear marker chain: 500 -> 400 -> 300 -> 200 -> 100 -> 0
	marker500 := &domain.Marker{
		ID:              "marker-500",
		Depth:           500,
		ParentMarkerIDs: []string{"marker-400"},
	}
	marker400 := &domain.Marker{
		ID:              "marker-400",
		Depth:           400,
		ParentMarkerIDs: []string{"marker-300"},
	}
	marker300 := &domain.Marker{
		ID:              "marker-300",
		Depth:           300,
		ParentMarkerIDs: []string{"marker-200"},
	}
	marker200 := &domain.Marker{
		ID:              "marker-200",
		Depth:           200,
		ParentMarkerIDs: []string{"marker-100"},
	}
	marker100 := &domain.Marker{ID: "marker-100", Depth: 100, ParentMarkerIDs: []string{"marker-0"}}
	marker0 := &domain.Marker{ID: "marker-0", Depth: 0, ParentMarkerIDs: []string{}}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{startKey}).
		Return([]domain.Vtxo{startVtxo}, nil)

	markerRepo.On("GetMarker", ctx, "marker-500").Return(marker500, nil)
	markerRepo.On("GetMarker", ctx, "marker-400").Return(marker400, nil)
	markerRepo.On("GetMarker", ctx, "marker-300").Return(marker300, nil)
	markerRepo.On("GetMarker", ctx, "marker-200").Return(marker200, nil)
	markerRepo.On("GetMarker", ctx, "marker-100").Return(marker100, nil)
	markerRepo.On("GetMarker", ctx, "marker-0").Return(marker0, nil)

	// Chain VTXOs from the bulk fetch
	chainVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "v-450", VOut: 0}, Depth: 450},
		{Outpoint: domain.Outpoint{Txid: "v-350", VOut: 0}, Depth: 350},
		{Outpoint: domain.Outpoint{Txid: "v-250", VOut: 0}, Depth: 250},
		{Outpoint: domain.Outpoint{Txid: "v-150", VOut: 0}, Depth: 150},
		{Outpoint: domain.Outpoint{Txid: "v-050", VOut: 0}, Depth: 50},
		{Outpoint: domain.Outpoint{Txid: "v-000", VOut: 0}, Depth: 0},
	}

	// All 6 markers should be collected
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		if len(ids) != 6 {
			return false
		}
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		return idSet["marker-500"] && idSet["marker-400"] && idSet["marker-300"] &&
			idSet["marker-200"] && idSet["marker-100"] && idSet["marker-0"]
	})).Return(chainVtxos, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// 6 chain VTXOs + 1 start VTXO = 7
	require.Len(t, cache, 7)
	require.Contains(t, cache, "deep-vtxo:0")
	require.Contains(t, cache, "v-450:0")
	require.Contains(t, cache, "v-350:0")
	require.Contains(t, cache, "v-250:0")
	require.Contains(t, cache, "v-150:0")
	require.Contains(t, cache, "v-050:0")
	require.Contains(t, cache, "v-000:0")

	// Verify every marker in the chain was visited
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-500")
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-400")
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-300")
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-200")
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-100")
	markerRepo.AssertCalled(t, "GetMarker", ctx, "marker-0")
}

// TestGetVtxosFromCacheOrDB_EmptyOutpoints verifies that an empty outpoints
// list returns an empty result without making any database call.
func TestGetVtxosFromCacheOrDB_EmptyOutpoints(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()
	cache := map[string]domain.Vtxo{
		"existing:0": {Outpoint: domain.Outpoint{Txid: "existing", VOut: 0}},
	}

	result, err := indexer.getVtxosFromCacheOrDB(ctx, []domain.Outpoint{}, cache)

	require.NoError(t, err)
	require.Empty(t, result)

	// DB should never be called for empty input
	vtxoRepo.AssertNotCalled(t, "GetVtxos", mock.Anything, mock.Anything)
}

// TestPrefetchVtxosByMarkers_CycleInMarkerDAG verifies that the BFS in
// prefetchVtxosByMarkers terminates when there is a cycle in the marker DAG
// (marker-A → parent marker-B → parent marker-A).
func TestPrefetchVtxosByMarkers_CycleInMarkerDAG(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "cycle-vtxo", VOut: 0}

	// Starting VTXO references marker-A
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "cycle-vtxo", VOut: 0},
		MarkerIDs: []string{"marker-A"},
		Depth:     200,
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "cycle-vtxo", VOut: 0}}).
		Return([]domain.Vtxo{startVtxo}, nil)

	// marker-A points to marker-B as parent
	markerRepo.On("GetMarker", ctx, "marker-A").Return(&domain.Marker{
		ID:              "marker-A",
		Depth:           200,
		ParentMarkerIDs: []string{"marker-B"},
	}, nil)

	// marker-B points BACK to marker-A (cycle!)
	markerRepo.On("GetMarker", ctx, "marker-B").Return(&domain.Marker{
		ID:              "marker-B",
		Depth:           100,
		ParentMarkerIDs: []string{"marker-A"},
	}, nil)

	// Both markers should be collected despite the cycle
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		if len(ids) != 2 {
			return false
		}
		idSet := make(map[string]bool)
		for _, id := range ids {
			idSet[id] = true
		}
		return idSet["marker-A"] && idSet["marker-B"]
	})).Return([]domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "chain-vtxo-1", VOut: 0}, Depth: 150},
	}, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// Should terminate and contain the start VTXO + chain VTXO
	require.Len(t, cache, 2)
	require.Contains(t, cache, "cycle-vtxo:0")
	require.Contains(t, cache, "chain-vtxo-1:0")

	// Each marker should be visited exactly once
	markerRepo.AssertNumberOfCalls(t, "GetMarker", 2)
}

// TestPrefetchVtxosByMarkers_StartVtxoNotFound verifies that when the starting
// VTXO is not found in the database, an empty cache is returned.
func TestPrefetchVtxosByMarkers_StartVtxoNotFound(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "nonexistent", VOut: 0}

	// GetVtxos returns empty slice (VTXO not found)
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "nonexistent", VOut: 0}}).
		Return([]domain.Vtxo{}, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	require.Empty(t, cache)
	// Marker repo should never be touched
	markerRepo.AssertNotCalled(t, "GetMarker", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "GetVtxoChainByMarkers", mock.Anything, mock.Anything)
}

// TestPrefetchVtxosByMarkers_Depth20k verifies that the BFS traversal in
// prefetchVtxosByMarkers correctly handles a VTXO at depth 20000 with a chain
// of 200 markers (one every 100 depths). This is the target maximum depth.
func TestPrefetchVtxosByMarkers_Depth20k(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	startKey := Outpoint{Txid: "deep-20k-vtxo", VOut: 0}

	const maxDepth = 20000
	const markerInterval = 100
	const numMarkers = maxDepth / markerInterval // 200 markers

	// Starting VTXO at depth 20000 with marker at depth 20000
	startVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "deep-20k-vtxo", VOut: 0},
		MarkerIDs: []string{fmt.Sprintf("marker-%d", maxDepth)},
		Depth:     maxDepth,
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "deep-20k-vtxo", VOut: 0}}).
		Return([]domain.Vtxo{startVtxo}, nil)

	// Build the 200-marker chain: marker-20000 -> marker-19900 -> ... -> marker-100 -> marker-0
	for depth := uint32(maxDepth); depth > 0; depth -= markerInterval {
		parentDepth := depth - markerInterval
		markerID := fmt.Sprintf("marker-%d", depth)
		parentMarkerID := fmt.Sprintf("marker-%d", parentDepth)
		markerRepo.On("GetMarker", ctx, markerID).Return(&domain.Marker{
			ID:              markerID,
			Depth:           depth,
			ParentMarkerIDs: []string{parentMarkerID},
		}, nil)
	}
	// Root marker at depth 0 has no parents
	markerRepo.On("GetMarker", ctx, "marker-0").Return(&domain.Marker{
		ID:              "marker-0",
		Depth:           0,
		ParentMarkerIDs: []string{},
	}, nil)

	// Generate VTXOs that would be returned by GetVtxoChainByMarkers
	// One VTXO per marker interval midpoint to simulate a populated chain
	chainVtxos := make([]domain.Vtxo, 0, numMarkers)
	for i := 0; i < numMarkers; i++ {
		chainVtxos = append(chainVtxos, domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: fmt.Sprintf("chain-vtxo-%d", i),
				VOut: 0,
			},
			Depth: uint32(i*markerInterval + 50), // midpoint of each interval
		})
	}

	// All 201 markers (0, 100, 200, ..., 20000) should be collected
	markerRepo.On("GetVtxoChainByMarkers", ctx, mock.MatchedBy(func(ids []string) bool {
		return len(ids) == numMarkers+1 // 201 markers total
	})).Return(chainVtxos, nil)

	cache := indexer.prefetchVtxosByMarkers(ctx, startKey)

	// 200 chain VTXOs + 1 start VTXO = 201
	require.Len(t, cache, numMarkers+1)
	require.Contains(t, cache, "deep-20k-vtxo:0")

	// Verify a sample of chain VTXOs are in cache
	require.Contains(t, cache, "chain-vtxo-0:0")
	require.Contains(t, cache, "chain-vtxo-99:0")
	require.Contains(t, cache, "chain-vtxo-199:0")

	// All 201 markers should have been visited via GetMarker (200 non-root + 1 root)
	markerRepo.AssertNumberOfCalls(t, "GetMarker", numMarkers+1)
}

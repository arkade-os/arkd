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
	args := m.Called(ctx, markerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Vtxo), args.Error(1)
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

// TestEncodeDecodeChainCursor_RoundTrip verifies that encoding then decoding
// a frontier of outpoints returns the same outpoints.
func TestEncodeDecodeChainCursor_RoundTrip(t *testing.T) {
	frontier := []domain.Outpoint{
		{Txid: "abc123", VOut: 0},
		{Txid: "def456", VOut: 2},
		{Txid: "ghi789", VOut: 1},
	}

	token := encodeChainCursor(frontier)
	require.NotEmpty(t, token)

	decoded, err := decodeChainCursor(token)
	require.NoError(t, err)
	require.Equal(t, frontier, decoded)
}

// TestEncodeDecodeChainCursor_EmptyFrontier verifies that an empty frontier
// encodes to an empty string.
func TestEncodeDecodeChainCursor_EmptyFrontier(t *testing.T) {
	token := encodeChainCursor(nil)
	require.Empty(t, token)

	token = encodeChainCursor([]domain.Outpoint{})
	require.Empty(t, token)
}

// TestDecodeChainCursor_InvalidBase64 verifies that invalid base64 returns an error.
func TestDecodeChainCursor_InvalidBase64(t *testing.T) {
	_, err := decodeChainCursor("not-valid-base64!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid base64")
}

// TestDecodeChainCursor_InvalidJSON verifies that valid base64 but invalid JSON
// returns an error.
func TestDecodeChainCursor_InvalidJSON(t *testing.T) {
	// Encode something that is not valid JSON
	token := "bm90LWpzb24" // base64url of "not-json"
	_, err := decodeChainCursor(token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JSON")
}

// TestEnsureVtxosCached_AllCacheHits verifies that when all outpoints are already
// in the cache, no DB call is made.
func TestEnsureVtxosCached_AllCacheHits(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()
	cache := map[string]domain.Vtxo{
		"vtxo-1:0": {Outpoint: domain.Outpoint{Txid: "vtxo-1", VOut: 0}, Amount: 100},
		"vtxo-2:0": {Outpoint: domain.Outpoint{Txid: "vtxo-2", VOut: 0}, Amount: 200},
	}
	loadedMarkers := make(map[string]bool)

	outpoints := []domain.Outpoint{
		{Txid: "vtxo-1", VOut: 0},
		{Txid: "vtxo-2", VOut: 0},
	}

	err := indexer.ensureVtxosCached(ctx, outpoints, cache, loadedMarkers)
	require.NoError(t, err)

	// No DB call should be made
	vtxoRepo.AssertNotCalled(t, "GetVtxos", mock.Anything, mock.Anything)
}

// TestEnsureVtxosCached_CacheMissLoadsFromDBAndMarkerWindow verifies that cache
// misses trigger a DB lookup and marker window prefetch.
func TestEnsureVtxosCached_CacheMissLoadsFromDBAndMarkerWindow(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	outpoints := []domain.Outpoint{{Txid: "vtxo-miss", VOut: 0}}

	// DB returns VTXO with a marker
	dbVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-miss", VOut: 0},
		Amount:    500,
		MarkerIDs: []string{"marker-100"},
	}
	vtxoRepo.On("GetVtxos", ctx, outpoints).Return([]domain.Vtxo{dbVtxo}, nil)

	// Marker window returns additional VTXOs
	windowVtxos := []domain.Vtxo{
		{Outpoint: domain.Outpoint{Txid: "window-vtxo-1", VOut: 0}, Amount: 300},
		{Outpoint: domain.Outpoint{Txid: "window-vtxo-2", VOut: 0}, Amount: 400},
	}
	markerRepo.On("GetVtxosByMarker", ctx, "marker-100").Return(windowVtxos, nil)

	err := indexer.ensureVtxosCached(ctx, outpoints, cache, loadedMarkers)
	require.NoError(t, err)

	// Cache should contain the original VTXO plus window VTXOs
	require.Contains(t, cache, "vtxo-miss:0")
	require.Contains(t, cache, "window-vtxo-1:0")
	require.Contains(t, cache, "window-vtxo-2:0")

	// Marker should be marked as loaded
	require.True(t, loadedMarkers["marker-100"])
}

// TestEnsureVtxosCached_NilMarkerRepo verifies that when the marker repository
// is nil, ensureVtxosCached falls back to direct DB lookup without window prefetch.
func TestEnsureVtxosCached_NilMarkerRepo(t *testing.T) {
	vtxoRepo := &mockVtxoRepoForIndexer{}
	repoManager := &mockRepoManagerForIndexer{vtxos: vtxoRepo, markers: nil}
	indexer := &indexerService{repoManager: repoManager}

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	outpoints := []domain.Outpoint{{Txid: "vtxo-no-markers", VOut: 0}}
	dbVtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-no-markers", VOut: 0},
		Amount:    100,
		MarkerIDs: []string{"marker-X"},
	}
	vtxoRepo.On("GetVtxos", ctx, outpoints).Return([]domain.Vtxo{dbVtxo}, nil)

	err := indexer.ensureVtxosCached(ctx, outpoints, cache, loadedMarkers)
	require.NoError(t, err)

	// VTXO should be cached even without marker window loading
	require.Contains(t, cache, "vtxo-no-markers:0")
}

// TestEnsureVtxosCached_DBErrorPropagated verifies that database errors
// are properly propagated.
func TestEnsureVtxosCached_DBErrorPropagated(t *testing.T) {
	vtxoRepo, _, indexer := newTestIndexer()

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	outpoints := []domain.Outpoint{{Txid: "vtxo-err", VOut: 0}}
	vtxoRepo.On("GetVtxos", ctx, outpoints).
		Return(nil, fmt.Errorf("database error"))

	err := indexer.ensureVtxosCached(ctx, outpoints, cache, loadedMarkers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "database error")
}

// TestGetVtxoChain_InvalidPageToken verifies that an invalid page_token
// returns an error.
func TestGetVtxoChain_InvalidPageToken(t *testing.T) {
	_, _, indexer := newTestIndexer()

	ctx := context.Background()
	vtxoKey := Outpoint{Txid: "abc123", VOut: 0}

	_, err := indexer.GetVtxoChain(ctx, vtxoKey, nil, "invalid-token!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid page_token")
}

// TestGetVtxoChain_BackwardCompat_NilPageEmptyToken verifies that when
// page is nil and pageToken is empty, the VTXO not found error comes from
// the DB lookup (not from pagination parsing), confirming backward compat.
func TestGetVtxoChain_BackwardCompat_NilPageEmptyToken(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	vtxoKey := Outpoint{Txid: "root-vtxo", VOut: 0}

	// Return no VTXOs so the chain walk fails with "vtxo not found"
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoKey}).
		Return([]domain.Vtxo{}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	_, err := indexer.GetVtxoChain(ctx, vtxoKey, nil, "")

	// Error should be from the chain walk, not from pagination setup
	require.Error(t, err)
	require.Contains(t, err.Error(), "vtxo not found")
	require.NotContains(t, err.Error(), "invalid page_token")
}

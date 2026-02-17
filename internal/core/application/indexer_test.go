package application

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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

type mockOffchainTxRepoForIndexer struct {
	mock.Mock
}

func (m *mockOffchainTxRepoForIndexer) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	args := m.Called(ctx, txid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OffchainTx), args.Error(1)
}

func (m *mockOffchainTxRepoForIndexer) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	return nil
}

func (m *mockOffchainTxRepoForIndexer) Close() {}

type mockRepoManagerForIndexer struct {
	vtxos       *mockVtxoRepoForIndexer
	markers     *mockMarkerRepoForIndexer
	offchainTxs *mockOffchainTxRepoForIndexer
}

func (m *mockRepoManagerForIndexer) Events() domain.EventRepository { return nil }
func (m *mockRepoManagerForIndexer) Rounds() domain.RoundRepository { return nil }
func (m *mockRepoManagerForIndexer) Vtxos() domain.VtxoRepository   { return m.vtxos }
func (m *mockRepoManagerForIndexer) Markers() domain.MarkerRepository {
	if m.markers == nil {
		return nil
	}
	return m.markers
}
func (m *mockRepoManagerForIndexer) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m *mockRepoManagerForIndexer) OffchainTxs() domain.OffchainTxRepository {
	if m.offchainTxs == nil {
		return nil
	}
	return m.offchainTxs
}
func (m *mockRepoManagerForIndexer) Convictions() domain.ConvictionRepository { return nil }
func (m *mockRepoManagerForIndexer) Assets() domain.AssetRepository           { return nil }
func (m *mockRepoManagerForIndexer) Fees() domain.FeeRepository               { return nil }
func (m *mockRepoManagerForIndexer) Close()                                   {}

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

// newTestIndexerWithOffchain creates mock repos including offchain tx repo.
func newTestIndexerWithOffchain() (
	*mockVtxoRepoForIndexer,
	*mockMarkerRepoForIndexer,
	*mockOffchainTxRepoForIndexer,
	*indexerService,
) {
	vtxoRepo := &mockVtxoRepoForIndexer{}
	markerRepo := &mockMarkerRepoForIndexer{}
	offchainTxRepo := &mockOffchainTxRepoForIndexer{}
	repoManager := &mockRepoManagerForIndexer{
		vtxos: vtxoRepo, markers: markerRepo, offchainTxs: offchainTxRepo,
	}
	indexer := &indexerService{repoManager: repoManager}
	return vtxoRepo, markerRepo, offchainTxRepo, indexer
}

// makeCheckpointPSBT creates a base64-encoded PSBT with a single input from
// the given previous outpoint. Used to build test checkpoint transactions.
func makeCheckpointPSBT(t *testing.T, inputTxid string, inputVout uint32) string {
	t.Helper()
	prevHash, err := chainhash.NewHashFromStr(inputTxid)
	require.NoError(t, err)

	outPoint := wire.NewOutPoint(prevHash, inputVout)
	output := wire.NewTxOut(1000, []byte{0x51}) // OP_TRUE

	p, err := psbt.New(
		[]*wire.OutPoint{outPoint},
		[]*wire.TxOut{output},
		2, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	b64, err := p.B64Encode()
	require.NoError(t, err)
	return b64
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

// TestEnsureVtxosCached_MarkerDedupAvoidsDuplicateLoad verifies that
// loadedMarkers prevents redundant GetVtxosByMarker calls when the same
// marker is encountered across multiple ensureVtxosCached invocations.
func TestEnsureVtxosCached_MarkerDedupAvoidsDuplicateLoad(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	// First call: vtxo-1 has marker-A
	vtxo1 := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-1", VOut: 0},
		Amount:    100,
		MarkerIDs: []string{"marker-A"},
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "vtxo-1", VOut: 0}}).
		Return([]domain.Vtxo{vtxo1}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, "marker-A").
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "window-1", VOut: 0}, Amount: 200},
		}, nil).Once() // Expect exactly one call

	err := indexer.ensureVtxosCached(
		ctx,
		[]domain.Outpoint{{Txid: "vtxo-1", VOut: 0}},
		cache,
		loadedMarkers,
	)
	require.NoError(t, err)
	require.True(t, loadedMarkers["marker-A"])

	// Second call: vtxo-2 also has marker-A
	vtxo2 := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-2", VOut: 0},
		Amount:    300,
		MarkerIDs: []string{"marker-A"},
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "vtxo-2", VOut: 0}}).
		Return([]domain.Vtxo{vtxo2}, nil)

	err = indexer.ensureVtxosCached(
		ctx,
		[]domain.Outpoint{{Txid: "vtxo-2", VOut: 0}},
		cache,
		loadedMarkers,
	)
	require.NoError(t, err)

	// GetVtxosByMarker for marker-A should have been called only once
	markerRepo.AssertNumberOfCalls(t, "GetVtxosByMarker", 1)
}

// TestEnsureVtxosCached_GetVtxosByMarkerErrorSwallowed verifies that an error
// from GetVtxosByMarker is gracefully swallowed — the VTXO itself is still
// cached and the function returns no error.
func TestEnsureVtxosCached_GetVtxosByMarkerErrorSwallowed(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newTestIndexer()

	ctx := context.Background()
	cache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	vtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-ok", VOut: 0},
		Amount:    500,
		MarkerIDs: []string{"marker-bad"},
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: "vtxo-ok", VOut: 0}}).
		Return([]domain.Vtxo{vtxo}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, "marker-bad").
		Return(nil, fmt.Errorf("marker window load failed"))

	err := indexer.ensureVtxosCached(
		ctx,
		[]domain.Outpoint{{Txid: "vtxo-ok", VOut: 0}},
		cache,
		loadedMarkers,
	)

	// No error propagated
	require.NoError(t, err)
	// The VTXO itself is still in cache
	require.Contains(t, cache, "vtxo-ok:0")
	// Marker is marked as loaded (won't retry)
	require.True(t, loadedMarkers["marker-bad"])
}

// TestGetVtxoChain_DefaultPageSizeWithTokenOnly verifies that when page is nil
// but a pageToken is provided, the default page size (maxPageSizeVtxoChain=100)
// is used instead of returning the full chain.
func TestGetVtxoChain_DefaultPageSizeWithTokenOnly(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Get the first page with an explicit page size to obtain a token
	page := &Page{PageSize: 2}
	resp1, err := indexer.GetVtxoChain(ctx, vtxoKey, page, "")
	require.NoError(t, err)
	require.NotEmpty(t, resp1.NextPageToken)

	// Resume with token but nil page — should use default page size (100),
	// which is large enough to return the remaining chain in one shot.
	resp2, err := indexer.GetVtxoChain(ctx, vtxoKey, nil, resp1.NextPageToken)
	require.NoError(t, err)
	// Remaining chain: B(ark+cp) + C(ark) = 3 items, all fit in default page
	require.Equal(t, 3, len(resp2.Chain))
	require.Empty(t, resp2.NextPageToken)
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

// setupPreconfirmedChain sets up a chain of preconfirmed VTXOs for pagination tests.
// Returns the VTXOs, the starting outpoint, and configures all mock expectations.
// Chain: vtxo-A -> checkpoint(input=vtxo-B) -> vtxo-B -> checkpoint(input=vtxo-C) -> vtxo-C (terminal)
func setupPreconfirmedChain(
	t *testing.T,
	ctx context.Context,
	vtxoRepo *mockVtxoRepoForIndexer,
	markerRepo *mockMarkerRepoForIndexer,
	offchainTxRepo *mockOffchainTxRepoForIndexer,
) Outpoint {
	t.Helper()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)

	vtxoA := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidA, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    1000,
	}
	vtxoB := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidB, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    2000,
	}
	vtxoC := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidC, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    3000,
	}

	// VTXOs returned from DB
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidA, VOut: 0}}).
		Return([]domain.Vtxo{vtxoA}, nil)
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidB, VOut: 0}}).
		Return([]domain.Vtxo{vtxoB}, nil)
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidC, VOut: 0}}).
		Return([]domain.Vtxo{vtxoC}, nil)

	// Marker repo won't be used (no markers on these VTXOs)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// Checkpoint PSBTs: A's checkpoint points to B, B's checkpoint points to C
	cpA := makeCheckpointPSBT(t, txidB, 0)
	cpB := makeCheckpointPSBT(t, txidC, 0)

	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-a": cpA}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	return Outpoint{Txid: txidA, VOut: 0}
}

// TestGetVtxoChain_PaginationFirstPage verifies that the first page returns
// the expected number of items and a non-empty next_page_token when the chain
// exceeds the page size.
func TestGetVtxoChain_PaginationFirstPage(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Page size 2: vtxo-A produces 2 chain items (ark + checkpoint),
	// then vtxo-B triggers early termination.
	page := &Page{PageSize: 2}
	resp, err := indexer.GetVtxoChain(ctx, vtxoKey, page, "")

	require.NoError(t, err)
	require.Len(t, resp.Chain, 2)
	require.Equal(t, IndexerChainedTxTypeArk, resp.Chain[0].Type)
	require.Equal(t, IndexerChainedTxTypeCheckpoint, resp.Chain[1].Type)
	require.NotEmpty(t, resp.NextPageToken, "should have next page token")
}

// TestGetVtxoChain_PaginationResumeWithToken verifies that resuming with a
// page token continues the chain from where the previous page left off,
// eventually exhausting the chain with an empty token.
func TestGetVtxoChain_PaginationResumeWithToken(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Chain: A(ark+cp) -> B(ark+cp) -> C(ark) = 5 items total
	// Page size 2: page1=2, page2=2, page3=1
	page := &Page{PageSize: 2}

	// Page 1
	resp1, err := indexer.GetVtxoChain(ctx, vtxoKey, page, "")
	require.NoError(t, err)
	require.Len(t, resp1.Chain, 2)
	require.NotEmpty(t, resp1.NextPageToken)

	// Page 2: resume with token from page 1
	resp2, err := indexer.GetVtxoChain(ctx, vtxoKey, page, resp1.NextPageToken)
	require.NoError(t, err)
	require.Len(t, resp2.Chain, 2)
	require.NotEmpty(t, resp2.NextPageToken)

	// Page 3: resume with token from page 2
	resp3, err := indexer.GetVtxoChain(ctx, vtxoKey, page, resp2.NextPageToken)
	require.NoError(t, err)
	require.Len(t, resp3.Chain, 1)
	require.Empty(t, resp3.NextPageToken, "last page should have empty token")

	// Verify total items across all pages
	totalItems := len(resp1.Chain) + len(resp2.Chain) + len(resp3.Chain)
	require.Equal(t, 5, totalItems)

	// Verify chain types: each vtxo with checkpoints produces ark+checkpoint,
	// terminal vtxo (C) produces only ark.
	require.Equal(t, IndexerChainedTxTypeArk, resp3.Chain[0].Type)
}

// TestGetVtxoChain_ShortChainNoToken verifies that when the chain is shorter
// than the page size, all items are returned with an empty next_page_token.
func TestGetVtxoChain_ShortChainNoToken(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)

	// Single terminal preconfirmed VTXO (no checkpoints)
	vtxo := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidA, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    1000,
	}
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidA, VOut: 0}}).
		Return([]domain.Vtxo{vtxo}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	// Page size larger than chain
	page := &Page{PageSize: 100}
	resp, err := indexer.GetVtxoChain(ctx, Outpoint{Txid: txidA, VOut: 0}, page, "")

	require.NoError(t, err)
	require.Len(t, resp.Chain, 1) // Just the ark tx
	require.Empty(t, resp.NextPageToken, "short chain should have empty token")
	require.Equal(t, IndexerChainedTxTypeArk, resp.Chain[0].Type)
}

// TestGetVtxoChain_PageSizeRespected verifies that each page never exceeds the
// page size (with allowance for grouped items from a single VTXO).
func TestGetVtxoChain_PageSizeRespected(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Use page size 1 — each VTXO produces 2 items (ark+checkpoint) for A and B,
	// so pages will slightly overflow since items for one VTXO are emitted together.
	page := &Page{PageSize: 1}

	resp, err := indexer.GetVtxoChain(ctx, vtxoKey, page, "")
	require.NoError(t, err)

	// vtxo-A emits 2 items (ark + checkpoint) even though pageSize=1,
	// because all items for a VTXO are emitted together.
	require.Equal(t, 2, len(resp.Chain))
	require.NotEmpty(t, resp.NextPageToken)
}

package application

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
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
	outpoint domain.Outpoint,
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
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Marker), args.Error(1)
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
func (m *mockMarkerRepoForIndexer) SweepVtxoOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
	sweptAt int64,
) error {
	return nil
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

func (m *mockOffchainTxRepoForIndexer) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	args := m.Called(ctx, txids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.OffchainTx), args.Error(1)
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
func newChainTestIndexer() (
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
func newChainTestIndexerWithOffchain() (
	*mockVtxoRepoForIndexer,
	*mockMarkerRepoForIndexer,
	*mockOffchainTxRepoForIndexer,
	*indexerService,
) {
	vtxoRepo := &mockVtxoRepoForIndexer{}
	markerRepo := &mockMarkerRepoForIndexer{}
	offchainTxRepo := &mockOffchainTxRepoForIndexer{}
	// Default: bulk fetch returns empty so the fallback to GetOffchainTx is used.
	// Tests that want to verify bulk behavior can override with a more specific expectation.
	offchainTxRepo.On("GetOffchainTxsByTxids", mock.Anything, mock.Anything).
		Return([]*domain.OffchainTx{}, nil).Maybe()
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
	svc := &indexerService{}
	frontier := []domain.Outpoint{
		{Txid: "abc123", VOut: 0},
		{Txid: "def456", VOut: 2},
		{Txid: "ghi789", VOut: 1},
	}

	token := svc.encodeChainCursor(frontier)
	require.NotEmpty(t, token)

	decoded, err := svc.decodeChainCursor(token)
	require.NoError(t, err)
	require.Equal(t, frontier, decoded)
}

// TestEncodeDecodeChainCursor_EmptyFrontier verifies that an empty frontier
// encodes to an empty string.
func TestEncodeDecodeChainCursor_EmptyFrontier(t *testing.T) {
	svc := &indexerService{}
	token := svc.encodeChainCursor(nil)
	require.Empty(t, token)

	token = svc.encodeChainCursor([]domain.Outpoint{})
	require.Empty(t, token)
}

// TestDecodeChainCursor_InvalidBase64 verifies that invalid base64 returns an error.
func TestDecodeChainCursor_InvalidBase64(t *testing.T) {
	svc := &indexerService{}
	_, err := svc.decodeChainCursor("not-valid-base64!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid base64")
}

// TestDecodeChainCursor_InvalidJSON verifies that valid base64 but invalid JSON
// returns an error.
func TestDecodeChainCursor_InvalidJSON(t *testing.T) {
	svc := &indexerService{}
	// Encode something that is not valid JSON
	token := "bm90LWpzb24" // base64url of "not-json"
	_, err := svc.decodeChainCursor(token)
	require.Error(t, err)
}

// TestDecodeChainCursor_HMACRejectsForgery verifies that a cursor signed with
// one key is rejected by a service with a different key.
func TestDecodeChainCursor_HMACRejectsForgery(t *testing.T) {
	svc := &indexerService{cursorHMACKey: []byte("server-secret-key")}
	frontier := []domain.Outpoint{{Txid: "abc123", VOut: 0}}

	token := svc.encodeChainCursor(frontier)
	require.NotEmpty(t, token)

	// Valid decode with same key works.
	decoded, err := svc.decodeChainCursor(token)
	require.NoError(t, err)
	require.Equal(t, frontier, decoded)

	// Forge a cursor with a different key — should be rejected.
	forger := &indexerService{cursorHMACKey: []byte("attacker-key")}
	forgedToken := forger.encodeChainCursor([]domain.Outpoint{{Txid: "victim-vtxo", VOut: 0}})
	_, err = svc.decodeChainCursor(forgedToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signature mismatch")

	// Tampered cursor — modify one byte of a valid token.
	rawToken, _ := base64.RawURLEncoding.DecodeString(token)
	rawToken[0] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(rawToken)
	_, err = svc.decodeChainCursor(tampered)
	require.Error(t, err)
}

// TestDecodeChainCursor_HMACEdgeCases covers malicious and accidental misuse of
// the cursor field: truncated tokens, empty strings, unsigned cursors sent to a
// signing server, replaying a valid cursor after the HMAC portion is stripped, etc.
func TestDecodeChainCursor_HMACEdgeCases(t *testing.T) {
	svc := &indexerService{cursorHMACKey: []byte("server-secret-key")}
	frontier := []domain.Outpoint{{Txid: "abc123", VOut: 0}}
	validToken := svc.encodeChainCursor(frontier)

	t.Run("empty string", func(t *testing.T) {
		_, err := svc.decodeChainCursor("")
		require.Error(t, err)
	})

	t.Run("truncated token missing HMAC bytes", func(t *testing.T) {
		raw, err := base64.RawURLEncoding.DecodeString(validToken)
		require.NoError(t, err)
		// Strip the 32-byte HMAC, leaving only the JSON payload.
		truncated := base64.RawURLEncoding.EncodeToString(raw[:len(raw)-32])
		_, err = svc.decodeChainCursor(truncated)
		require.Error(t, err)
	})

	t.Run("unsigned cursor rejected by signing server", func(t *testing.T) {
		// A server with no HMAC key produces unsigned cursors.
		noKey := &indexerService{}
		unsigned := noKey.encodeChainCursor(frontier)
		// A server WITH an HMAC key must reject it.
		_, err := svc.decodeChainCursor(unsigned)
		require.Error(t, err)
	})

	t.Run("hand-crafted JSON without HMAC", func(t *testing.T) {
		// Attacker builds raw JSON and base64-encodes it, no HMAC.
		raw := []byte(`{"frontier":[{"txid":"victim","vout":0}]}`)
		crafted := base64.RawURLEncoding.EncodeToString(raw)
		_, err := svc.decodeChainCursor(crafted)
		require.Error(t, err)
	})

	t.Run("cursor from restarted server with new key", func(t *testing.T) {
		oldServer := &indexerService{cursorHMACKey: []byte("old-key")}
		oldToken := oldServer.encodeChainCursor(frontier)
		newServer := &indexerService{cursorHMACKey: []byte("new-key-after-restart")}
		_, err := newServer.decodeChainCursor(oldToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature mismatch")
	})

	t.Run("swapped payload same length", func(t *testing.T) {
		// Take a valid token, replace the JSON payload but keep the
		// original HMAC — should fail because HMAC won't match.
		raw, err := base64.RawURLEncoding.DecodeString(validToken)
		require.NoError(t, err)
		origHMAC := raw[len(raw)-32:]
		newPayload := []byte(`{"frontier":[{"txid":"other","vout":0}]}`)
		tampered := append(newPayload, origHMAC...)
		token := base64.RawURLEncoding.EncodeToString(tampered)
		_, err = svc.decodeChainCursor(token)
		require.Error(t, err)
	})
}

// TestEnsureVtxosCached_AllCacheHits verifies that when all outpoints are already
// in the cache, no DB call is made.
func TestEnsureVtxosCached_AllCacheHits(t *testing.T) {
	vtxoRepo, _, indexer := newChainTestIndexer()

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
	vtxoRepo, markerRepo, indexer := newChainTestIndexer()

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
	vtxoRepo, _, indexer := newChainTestIndexer()

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
	vtxoRepo, markerRepo, indexer := newChainTestIndexer()

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
	vtxoRepo, markerRepo, indexer := newChainTestIndexer()

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
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Get the first page with an explicit page size to obtain a token
	page := &Page{PageSize: 2}
	resp1, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, "")
	require.NoError(t, err)
	require.NotEmpty(t, resp1.NextPageToken)

	// Resume with token but nil page — should use default page size (100),
	// which is large enough to return the remaining chain in one shot.
	resp2, err := indexer.GetVtxoChain(ctx, "", vtxoKey, nil, resp1.NextPageToken)
	require.NoError(t, err)
	// Remaining chain: B(ark+cp) + C(ark) = 3 items, all fit in default page
	require.Equal(t, 3, len(resp2.Chain))
	require.Empty(t, resp2.NextPageToken)
}

// TestGetVtxoChain_InvalidPageToken verifies that an invalid page_token
// returns an error.
func TestGetVtxoChain_InvalidPageToken(t *testing.T) {
	_, _, indexer := newChainTestIndexer()

	ctx := context.Background()
	vtxoKey := Outpoint{Txid: "abc123", VOut: 0}

	_, err := indexer.GetVtxoChain(ctx, "", vtxoKey, nil, "invalid-token!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid page_token")
}

// TestGetVtxoChain_BackwardCompat_NilPageEmptyToken verifies that when
// page is nil and pageToken is empty, the VTXO not found error comes from
// the DB lookup (not from pagination parsing), confirming backward compat.
func TestGetVtxoChain_BackwardCompat_NilPageEmptyToken(t *testing.T) {
	vtxoRepo, markerRepo, indexer := newChainTestIndexer()

	ctx := context.Background()
	vtxoKey := Outpoint{Txid: "root-vtxo", VOut: 0}

	// Return no VTXOs so the chain walk fails with "vtxo not found"
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoKey}).
		Return([]domain.Vtxo{}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	_, err := indexer.GetVtxoChain(ctx, "", vtxoKey, nil, "")

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

	offchainTxA := &domain.OffchainTx{ArkTxid: txidA, CheckpointTxs: map[string]string{"cp-a": cpA}}
	offchainTxB := &domain.OffchainTx{ArkTxid: txidB, CheckpointTxs: map[string]string{"cp-b": cpB}}
	offchainTxC := &domain.OffchainTx{ArkTxid: txidC, CheckpointTxs: map[string]string{}}

	offchainTxRepo.On("GetOffchainTxsByTxids", ctx, []string{txidA}).
		Return([]*domain.OffchainTx{offchainTxA}, nil).Maybe()
	offchainTxRepo.On("GetOffchainTxsByTxids", ctx, []string{txidB}).
		Return([]*domain.OffchainTx{offchainTxB}, nil).Maybe()
	offchainTxRepo.On("GetOffchainTxsByTxids", ctx, []string{txidC}).
		Return([]*domain.OffchainTx{offchainTxC}, nil).Maybe()

	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(offchainTxA, nil).Maybe()
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(offchainTxB, nil).Maybe()
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(offchainTxC, nil).Maybe()

	return Outpoint{Txid: txidA, VOut: 0}
}

// TestGetVtxoChain_PaginationFirstPage verifies that the first page returns
// the expected number of items and a non-empty next_page_token when the chain
// exceeds the page size.
func TestGetVtxoChain_PaginationFirstPage(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Page size 2: vtxo-A produces 2 chain items (ark + checkpoint),
	// then vtxo-B triggers early termination.
	page := &Page{PageSize: 2}
	resp, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, "")

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
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Chain: A(ark+cp) -> B(ark+cp) -> C(ark) = 5 items total
	// Page size 2: page1=2, page2=2, page3=1
	page := &Page{PageSize: 2}

	// Page 1
	resp1, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, "")
	require.NoError(t, err)
	require.Len(t, resp1.Chain, 2)
	require.NotEmpty(t, resp1.NextPageToken)

	// Page 2: resume with token from page 1
	resp2, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, resp1.NextPageToken)
	require.NoError(t, err)
	require.Len(t, resp2.Chain, 2)
	require.NotEmpty(t, resp2.NextPageToken)

	// Page 3: resume with token from page 2
	resp3, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, resp2.NextPageToken)
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
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
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
	offchainTxA := &domain.OffchainTx{ArkTxid: txidA, CheckpointTxs: map[string]string{}}
	offchainTxRepo.On("GetOffchainTxsByTxids", ctx, []string{txidA}).
		Return([]*domain.OffchainTx{offchainTxA}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(offchainTxA, nil).Maybe()

	// Page size larger than chain
	page := &Page{PageSize: 100}
	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, page, "")

	require.NoError(t, err)
	require.Len(t, resp.Chain, 1) // Just the ark tx
	require.Empty(t, resp.NextPageToken, "short chain should have empty token")
	require.Equal(t, IndexerChainedTxTypeArk, resp.Chain[0].Type)
}

// TestGetVtxoChain_PageSizeRespected verifies that each page never exceeds the
// page size (with allowance for grouped items from a single VTXO).
func TestGetVtxoChain_PageSizeRespected(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	vtxoKey := setupPreconfirmedChain(t, ctx, vtxoRepo, markerRepo, offchainTxRepo)

	// Use page size 1 — each VTXO produces 2 items (ark+checkpoint) for A and B,
	// so pages will slightly overflow since items for one VTXO are emitted together.
	page := &Page{PageSize: 1}

	resp, err := indexer.GetVtxoChain(ctx, "", vtxoKey, page, "")
	require.NoError(t, err)

	// vtxo-A emits 2 items (ark + checkpoint) even though pageSize=1,
	// because all items for a VTXO are emitted together.
	require.Equal(t, 2, len(resp.Chain))
	require.NotEmpty(t, resp.NextPageToken)
}

// matchOutpoints returns a mock.MatchedBy matcher that matches a []domain.Outpoint
// argument containing exactly the given outpoints, regardless of order.
func matchOutpoints(expected ...domain.Outpoint) interface{} {
	sorted := make([]string, len(expected))
	for i, op := range expected {
		sorted[i] = op.String()
	}
	sort.Strings(sorted)
	return mock.MatchedBy(func(ops []domain.Outpoint) bool {
		if len(ops) != len(sorted) {
			return false
		}
		cp := make([]string, len(ops))
		for i, op := range ops {
			cp[i] = op.String()
		}
		sort.Strings(cp)
		for i := range cp {
			if cp[i] != sorted[i] {
				return false
			}
		}
		return true
	})
}

// matchIDs returns a mock.MatchedBy matcher that matches a []string argument
// containing exactly the given IDs, regardless of order. This avoids flakes from
// non-deterministic map iteration in preloadByMarkers.
func matchIDs(expected ...string) interface{} {
	sorted := make([]string, len(expected))
	copy(sorted, expected)
	sort.Strings(sorted)
	return mock.MatchedBy(func(ids []string) bool {
		if len(ids) != len(sorted) {
			return false
		}
		cp := make([]string, len(ids))
		copy(cp, ids)
		sort.Strings(cp)
		for i := range cp {
			if cp[i] != sorted[i] {
				return false
			}
		}
		return true
	})
}

// TestPreloadVtxosByMarkers_WalksMarkerChain verifies that preloadByMarkers
// follows the marker DAG upward and populates the cache with all discovered VTXOs.
func TestPreloadVtxosByMarkers_WalksMarkerChain(t *testing.T) {
	_, markerRepo, indexer := newChainTestIndexer()
	ctx := context.Background()

	// Chain: vtxo-leaf has marker-200, which has parent marker-100, which has parent marker-0.
	vtxoLeaf := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-leaf", VOut: 0},
		Amount:    100,
		MarkerIDs: []string{"marker-200"},
	}

	// GetVtxoChainByMarkers returns VTXOs for each marker level.
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-200")).
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "vtxo-200a", VOut: 0}, Amount: 200},
			{Outpoint: domain.Outpoint{Txid: "vtxo-200b", VOut: 0}, Amount: 201},
		}, nil)
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-100")).
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "vtxo-100a", VOut: 0}, Amount: 300},
		}, nil)
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-0")).
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "vtxo-0a", VOut: 0}, Amount: 400},
		}, nil)

	// GetMarkersByIds returns marker objects with parent pointers.
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-200")).
		Return([]domain.Marker{
			{ID: "marker-200", Depth: 200, ParentMarkerIDs: []string{"marker-100"}},
		}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-100")).
		Return([]domain.Marker{
			{ID: "marker-100", Depth: 100, ParentMarkerIDs: []string{"marker-0"}},
		}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-0")).
		Return([]domain.Marker{
			{ID: "marker-0", Depth: 0, ParentMarkerIDs: nil},
		}, nil)

	cache := make(map[string]domain.Vtxo)
	offchainCache := make(map[string]*domain.OffchainTx)
	err := indexer.preloadByMarkers(ctx, []domain.Vtxo{vtxoLeaf}, cache, offchainCache)
	require.NoError(t, err)

	// Cache should contain the seed vtxo plus all vtxos from all marker levels.
	require.Contains(t, cache, "vtxo-leaf:0")
	require.Contains(t, cache, "vtxo-200a:0")
	require.Contains(t, cache, "vtxo-200b:0")
	require.Contains(t, cache, "vtxo-100a:0")
	require.Contains(t, cache, "vtxo-0a:0")
	require.Len(t, cache, 5)

	markerRepo.AssertNumberOfCalls(t, "GetVtxoChainByMarkers", 3)
	markerRepo.AssertNumberOfCalls(t, "GetMarkersByIds", 3)
}

// TestPreloadVtxosByMarkers_NoCycleLoop verifies that the visited set prevents
// infinite loops when markers form a cycle.
func TestPreloadVtxosByMarkers_NoCycleLoop(t *testing.T) {
	_, markerRepo, indexer := newChainTestIndexer()
	ctx := context.Background()

	vtxo := domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: "vtxo-cycle", VOut: 0},
		Amount:    100,
		MarkerIDs: []string{"marker-A"},
	}

	// marker-A -> marker-B -> marker-A (cycle)
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-A")).
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "vtxo-a", VOut: 0}, Amount: 100},
		}, nil)
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-B")).
		Return([]domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "vtxo-b", VOut: 0}, Amount: 200},
		}, nil)

	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-A")).
		Return([]domain.Marker{
			{ID: "marker-A", Depth: 0, ParentMarkerIDs: []string{"marker-B"}},
		}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-B")).
		Return([]domain.Marker{
			{ID: "marker-B", Depth: 0, ParentMarkerIDs: []string{"marker-A"}},
		}, nil)

	cache := make(map[string]domain.Vtxo)
	offchainCache := make(map[string]*domain.OffchainTx)
	err := indexer.preloadByMarkers(ctx, []domain.Vtxo{vtxo}, cache, offchainCache)
	require.NoError(t, err)

	// Should terminate without looping forever.
	require.Contains(t, cache, "vtxo-cycle:0")
	require.Contains(t, cache, "vtxo-a:0")
	require.Contains(t, cache, "vtxo-b:0")

	// Each marker queried exactly once.
	markerRepo.AssertNumberOfCalls(t, "GetVtxoChainByMarkers", 2)
	markerRepo.AssertNumberOfCalls(t, "GetMarkersByIds", 2)
}

// TestGetVtxoChain_WithMarkers_UsesPreload verifies that GetVtxoChain uses
// preloadByMarkers when VTXOs have markers, and that the main loop
// hits the cache instead of making additional DB calls.
func TestGetVtxoChain_WithMarkers_UsesPreload(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)

	vtxoA := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidA, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    1000,
		MarkerIDs:    []string{"marker-200"},
	}
	vtxoB := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidB, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    2000,
		MarkerIDs:    []string{"marker-100"},
	}
	vtxoC := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidC, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    3000,
	}

	// Initial GetVtxos call for preload (frontier = [vtxoA]).
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidA, VOut: 0}}).
		Return([]domain.Vtxo{vtxoA}, nil)

	// Preload via marker chain: marker-200 -> marker-100 -> marker-0 (no parent).
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-200")).
		Return([]domain.Vtxo{vtxoA, vtxoB}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-200")).
		Return([]domain.Marker{
			{ID: "marker-200", Depth: 200, ParentMarkerIDs: []string{"marker-100"}},
		}, nil)
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-100")).
		Return([]domain.Vtxo{vtxoB, vtxoC}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("marker-100")).
		Return([]domain.Marker{
			{ID: "marker-100", Depth: 100, ParentMarkerIDs: nil},
		}, nil)

	// ensureVtxosCached will find cache hits for B and C (preloaded),
	// so no additional GetVtxos calls for them.
	// Marker window loading via GetVtxosByMarker is still called for markers on
	// cache misses, but since everything is preloaded there are no misses.
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// Offchain tx setup for preconfirmed chain.
	cpA := makeCheckpointPSBT(t, txidB, 0)
	cpB := makeCheckpointPSBT(t, txidC, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-a": cpA}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 5, len(resp.Chain)) // A(ark+cp) + B(ark+cp) + C(ark)

	// GetVtxoChainByMarkers should have been called (preload path used).
	markerRepo.AssertCalled(t, "GetVtxoChainByMarkers", ctx, matchIDs("marker-200"))
	markerRepo.AssertCalled(t, "GetVtxoChainByMarkers", ctx, matchIDs("marker-100"))

	// GetVtxos should only be called once (for the initial preload fetch),
	// not for B or C individually — they were already in the cache.
	vtxoRepo.AssertNumberOfCalls(t, "GetVtxos", 1)
}

// TestGetVtxoChain_PreloadReducesDBCalls builds a 500-VTXO preconfirmed chain
// with markers every 100 VTXOs and verifies that preloading reduces GetVtxos
// calls from ~500 (one per VTXO) to 1 (the initial frontier fetch).
func TestGetVtxoChain_PreloadReducesDBCalls(t *testing.T) {
	const chainLen = 500
	const markersCount = chainLen / int(domain.MarkerInterval) // 5

	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	// Generate txids and VTXOs grouped by marker bucket.
	txids := make([]string, chainLen)
	vtxos := make([]domain.Vtxo, chainLen)
	for i := 0; i < chainLen; i++ {
		txids[i] = fmt.Sprintf("%064x", i)
		markerID := fmt.Sprintf("m-%d", i/int(domain.MarkerInterval))
		vtxos[i] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: txids[i], VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
			MarkerIDs:    []string{markerID},
		}
	}

	// Preload: GetVtxos for frontier (single call).
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txids[0], VOut: 0}}).
		Return([]domain.Vtxo{vtxos[0]}, nil)

	// Preload: marker chain m-0 → m-1 → m-2 → m-3 → m-4.
	for m := 0; m < markersCount; m++ {
		mid := fmt.Sprintf("m-%d", m)
		batch := vtxos[m*int(domain.MarkerInterval) : (m+1)*int(domain.MarkerInterval)]

		markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs(mid)).
			Return(batch, nil)

		var parentIDs []string
		if m+1 < markersCount {
			parentIDs = []string{fmt.Sprintf("m-%d", m+1)}
		}
		markerRepo.On("GetMarkersByIds", ctx, matchIDs(mid)).
			Return([]domain.Marker{
				{ID: mid, Depth: uint32(m * int(domain.MarkerInterval)), ParentMarkerIDs: parentIDs},
			}, nil)
	}

	// Marker window (won't be called — all cache hits from preload).
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// Offchain tx: each vtxo_i has a checkpoint pointing to vtxo_{i+1}.
	for i := 0; i < chainLen-1; i++ {
		cp := makeCheckpointPSBT(t, txids[i+1], 0)
		offchainTxRepo.On("GetOffchainTx", ctx, txids[i]).
			Return(&domain.OffchainTx{
				CheckpointTxs: map[string]string{fmt.Sprintf("cp-%d", i): cp},
			}, nil)
	}
	// Terminal VTXO (no checkpoints).
	offchainTxRepo.On("GetOffchainTx", ctx, txids[chainLen-1]).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txids[0], VOut: 0}, nil, "")
	require.NoError(t, err)

	// Each non-terminal VTXO produces 2 items (ark + checkpoint), terminal produces 1.
	expectedItems := (chainLen-1)*2 + 1
	require.Equal(t, expectedItems, len(resp.Chain))

	// Key assertion: GetVtxos called only 1 time (preload frontier fetch).
	// Without preloading this would be ~500 individual DB calls.
	vtxoRepo.AssertNumberOfCalls(t, "GetVtxos", 1)

	// Marker-based preload: 5 bulk fetches + 5 marker lookups = 10 total queries.
	markerRepo.AssertNumberOfCalls(t, "GetVtxoChainByMarkers", markersCount)
	markerRepo.AssertNumberOfCalls(t, "GetMarkersByIds", markersCount)
}

// TestGetVtxoChain_PreloadMarkerErrorFallback verifies that when the marker
// repo errors during preloadByMarkers, GetVtxoChain still returns the correct
// chain via the per-hop GetVtxos + ensureVtxosCached fallback, rather than
// aborting the request entirely.
func TestGetVtxoChain_PreloadMarkerErrorFallback(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)

	vtxoA := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidA, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    1000,
		MarkerIDs:    []string{"marker-A"},
	}
	vtxoB := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidB, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    2000,
		MarkerIDs:    []string{"marker-B"},
	}
	vtxoC := domain.Vtxo{
		Outpoint:     domain.Outpoint{Txid: txidC, VOut: 0},
		Preconfirmed: true,
		ExpiresAt:    3000,
		MarkerIDs:    []string{"marker-C"},
	}

	// Initial preload fetch for the frontier.
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidA, VOut: 0}}).
		Return([]domain.Vtxo{vtxoA}, nil)

	// Preload's first marker lookup fails — this is the fault we're injecting.
	// Per-hop fallback should take over from here.
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("marker-A")).
		Return(nil, fmt.Errorf("transient marker repo failure"))

	// ensureVtxosCached fetches B and C on cache miss. The fix lets these run
	// even though preload aborted partway through.
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidB, VOut: 0}}).
		Return([]domain.Vtxo{vtxoB}, nil)
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{{Txid: txidC, VOut: 0}}).
		Return([]domain.Vtxo{vtxoC}, nil)

	// Marker window loading during the walk — can either succeed empty or
	// error; ensureVtxosCached logs and continues either way.
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// Offchain tx for the preconfirmed chain: A → B → C.
	cpA := makeCheckpointPSBT(t, txidB, 0)
	cpB := makeCheckpointPSBT(t, txidC, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-a": cpA}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err, "marker preload failure must not abort GetVtxoChain")
	require.Equal(t, 5, len(resp.Chain)) // A(ark+cp) + B(ark+cp) + C(ark)

	// The preload GetVtxoChainByMarkers was attempted (and failed).
	markerRepo.AssertCalled(t, "GetVtxoChainByMarkers", ctx, matchIDs("marker-A"))
	// And the fallback did per-hop GetVtxos for B and C (plus the initial A).
	vtxoRepo.AssertNumberOfCalls(t, "GetVtxos", 3)
}

// TestGetVtxoChain_Fanout verifies that a VTXO with 2 checkpoints pointing
// to different parents correctly traverses both branches.
//
//	A --(cp1)--> B
//	A --(cp2)--> C
func TestGetVtxoChain_Fanout(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)

	vtxoA := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidA, VOut: 0}, Preconfirmed: true, ExpiresAt: 1000}
	vtxoB := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidB, VOut: 0}, Preconfirmed: true, ExpiresAt: 2000}
	vtxoC := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidC, VOut: 0}, Preconfirmed: true, ExpiresAt: 3000}

	// Preload frontier fetch
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoA.Outpoint}).
		Return([]domain.Vtxo{vtxoA}, nil)
	// ensureVtxosCached for B and C (order-independent)
	vtxoRepo.On("GetVtxos", ctx, matchOutpoints(vtxoB.Outpoint, vtxoC.Outpoint)).
		Return([]domain.Vtxo{vtxoB, vtxoC}, nil)

	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// A has 2 checkpoints: one to B, one to C
	cpB := makeCheckpointPSBT(t, txidB, 0)
	cpC := makeCheckpointPSBT(t, txidC, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB, "cp-c": cpC}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err)

	// A: ark + 2 checkpoints = 3. B: ark = 1. C: ark = 1. Total: 5.
	require.Equal(t, 5, len(resp.Chain))

	// A is always the first ark tx
	require.Equal(t, txidA, resp.Chain[0].Txid)
	require.Equal(t, IndexerChainedTxTypeArk, resp.Chain[0].Type)
	require.Len(t, resp.Chain[0].Spends, 2)

	// Count chain item types
	arkCount, cpCount := 0, 0
	for _, item := range resp.Chain {
		switch item.Type {
		case IndexerChainedTxTypeArk:
			arkCount++
		case IndexerChainedTxTypeCheckpoint:
			cpCount++
		}
	}
	require.Equal(t, 3, arkCount)
	require.Equal(t, 2, cpCount)
}

// TestGetVtxoChain_Diamond verifies that two paths converging on the same
// ancestor VTXO only process that ancestor once.
//
//	A --(cp1)--> B --(cp)--> D
//	A --(cp2)--> C --(cp)--> D  (same D)
func TestGetVtxoChain_Diamond(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)
	txidD := strings.Repeat("d", 64)

	vtxoA := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidA, VOut: 0}, Preconfirmed: true, ExpiresAt: 1000}
	vtxoB := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidB, VOut: 0}, Preconfirmed: true, ExpiresAt: 2000}
	vtxoC := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidC, VOut: 0}, Preconfirmed: true, ExpiresAt: 3000}
	vtxoD := domain.Vtxo{Outpoint: domain.Outpoint{Txid: txidD, VOut: 0}, Preconfirmed: true, ExpiresAt: 4000}

	// Preload frontier
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoA.Outpoint}).
		Return([]domain.Vtxo{vtxoA}, nil)
	// B and C fetched together (order varies due to map iteration)
	vtxoRepo.On("GetVtxos", ctx, matchOutpoints(vtxoB.Outpoint, vtxoC.Outpoint)).
		Return([]domain.Vtxo{vtxoB, vtxoC}, nil)
	// D appears as [D, D] because both B and C point to it before D is visited.
	vtxoRepo.On("GetVtxos", ctx, mock.MatchedBy(func(ops []domain.Outpoint) bool {
		for _, op := range ops {
			if op.String() != vtxoD.Outpoint.String() {
				return false
			}
		}
		return len(ops) > 0
	})).Return([]domain.Vtxo{vtxoD}, nil)

	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// A fans out to B and C
	cpB := makeCheckpointPSBT(t, txidB, 0)
	cpC := makeCheckpointPSBT(t, txidC, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB, "cp-c": cpC}}, nil)

	// B converges to D
	cpBD := makeCheckpointPSBT(t, txidD, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-bd": cpBD}}, nil)

	// C converges to same D
	cpCD := makeCheckpointPSBT(t, txidD, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-cd": cpCD}}, nil)

	// D is terminal
	offchainTxRepo.On("GetOffchainTx", ctx, txidD).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err)

	// A: ark + 2cp = 3. B: ark + 1cp = 2. C: ark + 1cp = 2. D: ark = 1. Total: 8.
	require.Equal(t, 8, len(resp.Chain))

	// D must appear exactly once despite convergence from B and C.
	dCount := 0
	for _, item := range resp.Chain {
		if item.Txid == txidD {
			dCount++
		}
	}
	require.Equal(t, 1, dCount, "converged VTXO D should appear exactly once")
}

// TestGetVtxoChain_MarkerBoundaryStart verifies that a chain starting exactly
// at marker boundary depth 0 preloads correctly (no parents to walk).
func TestGetVtxoChain_MarkerBoundaryStart(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)

	vtxoA := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txidA, VOut: 0}, Preconfirmed: true,
		ExpiresAt: 1000, MarkerIDs: []string{"m-0"},
	}
	vtxoB := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txidB, VOut: 0}, Preconfirmed: true,
		ExpiresAt: 2000, MarkerIDs: []string{"m-0"},
	}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoA.Outpoint}).
		Return([]domain.Vtxo{vtxoA}, nil)

	// Preload: marker m-0 at depth 0 with no parents.
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("m-0")).
		Return([]domain.Vtxo{vtxoA, vtxoB}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("m-0")).
		Return([]domain.Marker{
			{ID: "m-0", Depth: 0, ParentMarkerIDs: nil},
		}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	cpB := makeCheckpointPSBT(t, txidB, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 3, len(resp.Chain)) // A(ark) + cp + B(ark)

	// Both VTXOs were preloaded via marker — only the frontier fetch needed.
	vtxoRepo.AssertNumberOfCalls(t, "GetVtxos", 1)
}

// TestGetVtxoChain_OverlappingMarkers verifies correct deduplication when a
// VTXO has multiple markers and one marker is both directly attached AND
// a parent of another marker.
//
//	A (markers: m-a, m-b) -> B (marker: m-b) -> C (no markers)
//	m-a has parent m-b, so m-b is already visited when discovered as parent.
func TestGetVtxoChain_OverlappingMarkers(t *testing.T) {
	vtxoRepo, markerRepo, offchainTxRepo, indexer := newChainTestIndexerWithOffchain()
	ctx := context.Background()

	txidA := strings.Repeat("a", 64)
	txidB := strings.Repeat("b", 64)
	txidC := strings.Repeat("c", 64)

	vtxoA := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txidA, VOut: 0}, Preconfirmed: true,
		ExpiresAt: 1000, MarkerIDs: []string{"m-a", "m-b"},
	}
	vtxoB := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txidB, VOut: 0}, Preconfirmed: true,
		ExpiresAt: 2000, MarkerIDs: []string{"m-b"},
	}
	vtxoC := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txidC, VOut: 0}, Preconfirmed: true,
		ExpiresAt: 3000,
	}

	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoA.Outpoint}).
		Return([]domain.Vtxo{vtxoA}, nil)

	// Preload: m-a and m-b fetched together. m-a's parent m-b is already visited.
	markerRepo.On("GetVtxoChainByMarkers", ctx, matchIDs("m-a", "m-b")).
		Return([]domain.Vtxo{vtxoA, vtxoB}, nil)
	markerRepo.On("GetMarkersByIds", ctx, matchIDs("m-a", "m-b")).
		Return([]domain.Marker{
			{ID: "m-a", Depth: 200, ParentMarkerIDs: []string{"m-b"}},
			{ID: "m-b", Depth: 100, ParentMarkerIDs: nil},
		}, nil)
	markerRepo.On("GetVtxosByMarker", ctx, mock.Anything).
		Return([]domain.Vtxo{}, nil).Maybe()

	// C not in any marker group — cache miss triggers DB fetch.
	vtxoRepo.On("GetVtxos", ctx, []domain.Outpoint{vtxoC.Outpoint}).
		Return([]domain.Vtxo{vtxoC}, nil)

	cpB := makeCheckpointPSBT(t, txidB, 0)
	cpC := makeCheckpointPSBT(t, txidC, 0)
	offchainTxRepo.On("GetOffchainTx", ctx, txidA).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-b": cpB}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidB).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{"cp-c": cpC}}, nil)
	offchainTxRepo.On("GetOffchainTx", ctx, txidC).
		Return(&domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil)

	resp, err := indexer.GetVtxoChain(ctx, "", Outpoint{Txid: txidA, VOut: 0}, nil, "")
	require.NoError(t, err)
	require.Equal(t, 5, len(resp.Chain))

	// 1 preload frontier + 1 for C (cache miss). A and B were preloaded via markers.
	vtxoRepo.AssertNumberOfCalls(t, "GetVtxos", 2)
	// Only 1 batch of marker fetches (m-a + m-b together; m-b's parent already visited).
	markerRepo.AssertNumberOfCalls(t, "GetVtxoChainByMarkers", 1)
	markerRepo.AssertNumberOfCalls(t, "GetMarkersByIds", 1)
}

package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for sweeper tests

type mockWalletService struct {
	mock.Mock
}

func (m *mockWalletService) BroadcastTransaction(
	ctx context.Context,
	txs ...string,
) (string, error) {
	args := m.Called(ctx, txs)
	return args.String(0), args.Error(1)
}

func (m *mockWalletService) GetTransaction(ctx context.Context, txid string) (string, error) {
	args := m.Called(ctx, txid)
	return args.String(0), args.Error(1)
}

// Stub implementations for unused WalletService methods
func (m *mockWalletService) GetReadyUpdate(ctx context.Context) (<-chan struct{}, error) {
	return nil, nil
}
func (m *mockWalletService) GenSeed(ctx context.Context) (string, error) { return "", nil }
func (m *mockWalletService) Create(ctx context.Context, seed, password string) error {
	return nil
}
func (m *mockWalletService) Restore(ctx context.Context, seed, password string) error {
	return nil
}
func (m *mockWalletService) Unlock(ctx context.Context, password string) error { return nil }
func (m *mockWalletService) Lock(ctx context.Context) error                    { return nil }
func (m *mockWalletService) Status(ctx context.Context) (ports.WalletStatus, error) {
	return nil, nil
}
func (m *mockWalletService) GetNetwork(ctx context.Context) (*arklib.Network, error) {
	return nil, nil
}
func (m *mockWalletService) GetForfeitPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	return nil, nil
}
func (m *mockWalletService) DeriveConnectorAddress(ctx context.Context) (string, error) {
	return "", nil
}
func (m *mockWalletService) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	return nil, nil
}

func (m *mockWalletService) SignTransaction(
	ctx context.Context,
	tx string,
	extractRawTx bool,
) (string, error) {
	return "", nil
}

func (m *mockWalletService) SignTransactionTapscript(
	ctx context.Context,
	tx string,
	inputIndexes []int,
) (string, error) {
	return "", nil
}

func (m *mockWalletService) SelectUtxos(
	ctx context.Context,
	asset string,
	amount uint64,
	confirmedOnly bool,
) ([]ports.TxInput, uint64, error) {
	return nil, 0, nil
}
func (m *mockWalletService) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	return 0, nil
}
func (m *mockWalletService) FeeRate(ctx context.Context) (uint64, error) { return 0, nil }

func (m *mockWalletService) ListConnectorUtxos(
	ctx context.Context,
	addr string,
) ([]ports.TxInput, error) {
	return nil, nil
}
func (m *mockWalletService) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return 0, 0, nil
}
func (m *mockWalletService) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return 0, 0, nil
}
func (m *mockWalletService) LockConnectorUtxos(ctx context.Context, utxos []domain.Outpoint) error {
	return nil
}
func (m *mockWalletService) GetDustAmount(ctx context.Context) (uint64, error) { return 0, nil }

func (m *mockWalletService) GetOutpointStatus(
	ctx context.Context,
	outpoint domain.Outpoint,
) (bool, error) {
	return false, nil
}

func (m *mockWalletService) GetCurrentBlockTime(
	ctx context.Context,
) (*ports.BlockTimestamp, error) {
	return nil, nil
}

func (m *mockWalletService) Withdraw(
	ctx context.Context,
	address string,
	amount uint64,
	all bool,
) (string, error) {
	return "", nil
}
func (m *mockWalletService) LoadSignerKey(ctx context.Context, prvkey string) error { return nil }
func (m *mockWalletService) Close()                                                 {}
func (m *mockWalletService) WatchScripts(ctx context.Context, scripts []string) error {
	return nil
}
func (m *mockWalletService) UnwatchScripts(ctx context.Context, scripts []string) error {
	return nil
}

func (m *mockWalletService) GetNotificationChannel(
	ctx context.Context,
) <-chan map[string][]ports.VtxoWithValue {
	return nil
}

func (m *mockWalletService) IsTransactionConfirmed(
	ctx context.Context,
	txid string,
) (bool, *ports.BlockTimestamp, error) {
	return false, nil, nil
}
func (m *mockWalletService) RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error {
	return nil
}

type mockVtxoRepository struct {
	mock.Mock
}

func (m *mockVtxoRepository) GetAllChildrenVtxos(
	ctx context.Context,
	txid string,
) ([]domain.Outpoint, error) {
	args := m.Called(ctx, txid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Outpoint), args.Error(1)
}

func (m *mockVtxoRepository) GetVtxos(
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
func (m *mockVtxoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error { return nil }

func (m *mockVtxoRepository) SettleVtxos(
	ctx context.Context,
	spentVtxos map[domain.Outpoint]string,
	commitmentTxid string,
) error {
	return nil
}

func (m *mockVtxoRepository) SpendVtxos(
	ctx context.Context,
	spentVtxos map[domain.Outpoint]string,
	arkTxid string,
) error {
	return nil
}
func (m *mockVtxoRepository) UnrollVtxos(ctx context.Context, outpoints []domain.Outpoint) error {
	return nil
}

func (m *mockVtxoRepository) GetAllNonUnrolledVtxos(
	ctx context.Context,
	pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	return nil, nil, nil
}

func (m *mockVtxoRepository) GetAllSweepableUnrolledVtxos(
	ctx context.Context,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockVtxoRepository) GetAllVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetAllVtxosWithPubKeys(
	ctx context.Context,
	pubkeys []string,
	after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetExpiringLiquidity(
	ctx context.Context,
	after, before int64,
) (uint64, error) {
	return 0, nil
}
func (m *mockVtxoRepository) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (m *mockVtxoRepository) UpdateVtxosExpiration(
	ctx context.Context,
	outpoints []domain.Outpoint,
	expiresAt int64,
) error {
	return nil
}

func (m *mockVtxoRepository) GetLeafVtxosForBatch(
	ctx context.Context,
	txid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
) ([]domain.Outpoint, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetVtxoPubKeysByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
	withMinimumAmount uint64,
) ([]string, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetPendingSpentVtxosWithPubKeys(
	ctx context.Context,
	pubkeys []string,
	after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockVtxoRepository) Close() {}

type mockMarkerRepository struct {
	mock.Mock
}

func (m *mockMarkerRepository) BulkSweepMarkers(
	ctx context.Context,
	markerIDs []string,
	sweptAt int64,
) error {
	args := m.Called(ctx, markerIDs, sweptAt)
	return args.Error(0)
}

// Stub implementations for unused MarkerRepository methods
func (m *mockMarkerRepository) AddMarker(ctx context.Context, marker domain.Marker) error {
	return nil
}
func (m *mockMarkerRepository) GetMarker(ctx context.Context, id string) (*domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetMarkersByDepth(
	ctx context.Context,
	depth uint32,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetMarkersByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetMarkersByIds(
	ctx context.Context,
	ids []string,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) SweepMarker(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) error {
	return nil
}

func (m *mockMarkerRepository) SweepMarkerWithDescendants(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) (int64, error) {
	return 0, nil
}
func (m *mockMarkerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	return false, nil
}

func (m *mockMarkerRepository) GetSweptMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.SweptMarker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) UpdateVtxoMarkers(
	ctx context.Context,
	outpoint domain.Outpoint,
	markerIDs []string,
) error {
	return nil
}

func (m *mockMarkerRepository) GetVtxosByMarker(
	ctx context.Context,
	markerID string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) SweepVtxosByMarker(
	ctx context.Context,
	markerID string,
) (int64, error) {
	return 0, nil
}

func (m *mockMarkerRepository) CreateRootMarkersForVtxos(
	ctx context.Context,
	vtxos []domain.Vtxo,
) error {
	return nil
}

func (m *mockMarkerRepository) GetVtxosByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetVtxosByArkTxid(
	ctx context.Context,
	arkTxid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetVtxoChainByMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockMarkerRepository) Close() {}

type mockTxBuilder struct {
	mock.Mock
}

func (m *mockTxBuilder) BuildSweepTx(inputs []ports.TxInput) (string, string, error) {
	args := m.Called(inputs)
	return args.String(0), args.String(1), args.Error(2)
}

// Stub implementations for unused TxBuilder methods
func (m *mockTxBuilder) BuildCommitmentTx(
	signerPubkey *btcec.PublicKey, intents domain.Intents,
	boardingInputs []ports.BoardingInput, cosigners [][]string,
) (string, *tree.TxTree, string, *tree.TxTree, error) {
	return "", nil, "", nil, nil
}

func (m *mockTxBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo,
	connectors tree.FlatTxTree,
	txs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	return nil, nil
}

func (m *mockTxBuilder) GetSweepableBatchOutputs(
	vtxoTree *tree.TxTree,
) (*arklib.RelativeLocktime, *ports.TxInput, error) {
	return nil, nil, nil
}
func (m *mockTxBuilder) FinalizeAndExtract(tx string) (string, error) { return "", nil }

func (m *mockTxBuilder) VerifyVtxoTapscriptSigs(
	tx string,
	mustIncludeSignerSig bool,
) (bool, *psbt.Packet, error) {
	return false, nil, nil
}

func (m *mockTxBuilder) VerifyBoardingTapscriptSigs(
	signedTx string,
	commitmentTx string,
) (map[uint32]ports.SignedBoardingInput, error) {
	return nil, nil
}

type mockRepoManager struct {
	vtxos   *mockVtxoRepository
	markers *mockMarkerRepository
}

func (m *mockRepoManager) Events() domain.EventRepository                { return nil }
func (m *mockRepoManager) Rounds() domain.RoundRepository                { return nil }
func (m *mockRepoManager) Vtxos() domain.VtxoRepository                  { return m.vtxos }
func (m *mockRepoManager) Markers() domain.MarkerRepository              { return m.markers }
func (m *mockRepoManager) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m *mockRepoManager) OffchainTxs() domain.OffchainTxRepository      { return nil }
func (m *mockRepoManager) Convictions() domain.ConvictionRepository      { return nil }
func (m *mockRepoManager) Assets() domain.AssetRepository                { return nil }
func (m *mockRepoManager) Fees() domain.FeeRepository                    { return nil }
func (m *mockRepoManager) Close()                                        {}

type mockScheduler struct{}

func (m *mockScheduler) Start()                                       {}
func (m *mockScheduler) Stop()                                        {}
func (m *mockScheduler) Unit() ports.TimeUnit                         { return ports.UnixTime }
func (m *mockScheduler) AfterNow(expiry int64) bool                   { return false }
func (m *mockScheduler) ScheduleTaskOnce(at int64, task func()) error { return nil }

// newTestSweeper creates a fresh set of mocks and a sweeper instance for testing.
func newTestSweeper() (
	*mockWalletService,
	*mockVtxoRepository,
	*mockMarkerRepository,
	*mockTxBuilder,
	*sweeper,
) {
	wallet := &mockWalletService{}
	vtxoRepo := &mockVtxoRepository{}
	markerRepo := &mockMarkerRepository{}
	repoManager := &mockRepoManager{vtxos: vtxoRepo, markers: markerRepo}
	builder := &mockTxBuilder{}
	scheduler := &mockScheduler{}
	s := newSweeper(wallet, repoManager, builder, scheduler, "")
	return wallet, vtxoRepo, markerRepo, builder, s
}

// TestCreateCheckpointSweepTask_BulkSweepsMarkers verifies that when a checkpoint
// is swept, the sweeper correctly collects all unique marker IDs from the affected
// VTXOs and calls BulkSweepMarkers with the deduplicated set. This tests the core
// optimization where multiple VTXOs sharing markers result in fewer marker sweep
// operations (3 VTXOs with overlapping markers should yield only 3 unique markers).
func TestCreateCheckpointSweepTask_BulkSweepsMarkers(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	// Test data
	checkpointTxid := "checkpoint123"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo123", VOut: 0}

	// Child VTXOs that will be returned by GetAllChildrenVtxos
	childOutpoints := []domain.Outpoint{
		{Txid: "child1", VOut: 0},
		{Txid: "child2", VOut: 0},
		{Txid: "child3", VOut: 0},
	}

	// VTXOs with markers - note some share markers to test deduplication
	vtxosWithMarkers := []domain.Vtxo{
		{
			Outpoint:  childOutpoints[0],
			MarkerIDs: []string{"marker-A", "marker-B"},
			Depth:     50,
		},
		{
			Outpoint:  childOutpoints[1],
			MarkerIDs: []string{"marker-B", "marker-C"}, // marker-B is shared
			Depth:     75,
		},
		{
			Outpoint:  childOutpoints[2],
			MarkerIDs: []string{"marker-A"}, // marker-A is shared
			Depth:     100,
		},
	}

	// Setup mock expectations
	toSweep := ports.TxInput{
		Txid:  checkpointTxid,
		Index: 0,
		Value: 10000,
	}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid123", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid123", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosWithMarkers, nil)

	// Expect BulkSweepMarkers to be called with deduplicated markers
	// Should have: marker-A, marker-B, marker-C (3 unique markers)
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.MatchedBy(func(markerIDs []string) bool {
		// Verify we have exactly 3 unique markers
		if len(markerIDs) != 3 {
			return false
		}
		// Verify all expected markers are present
		markerSet := make(map[string]bool)
		for _, id := range markerIDs {
			markerSet[id] = true
		}
		return markerSet["marker-A"] && markerSet["marker-B"] && markerSet["marker-C"]
	}), mock.AnythingOfType("int64")).Return(nil)

	// Execute the sweep task
	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify
	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	markerRepo.AssertExpectations(t)
	builder.AssertExpectations(t)
}

// TestCreateCheckpointSweepTask_NoMarkersSkipsSweep verifies that when VTXOs have
// no markers (empty MarkerIDs slice), the sweeper does not call BulkSweepMarkers.
// This is an edge case that could occur with legacy VTXOs or during error recovery,
// and ensures the sweeper handles it gracefully without attempting empty bulk operations.
func TestCreateCheckpointSweepTask_NoMarkersSkipsSweep(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	// Test data
	checkpointTxid := "checkpoint456"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo456", VOut: 0}

	// Child VTXOs with no markers (empty MarkerIDs)
	childOutpoints := []domain.Outpoint{
		{Txid: "child1", VOut: 0},
	}

	vtxosWithoutMarkers := []domain.Vtxo{
		{
			Outpoint:  childOutpoints[0],
			MarkerIDs: []string{}, // No markers
			Depth:     0,
		},
	}

	// Setup mock expectations
	toSweep := ports.TxInput{
		Txid:  checkpointTxid,
		Index: 0,
		Value: 10000,
	}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid456", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid456", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosWithoutMarkers, nil)

	// BulkSweepMarkers should NOT be called since there are no markers

	// Execute the sweep task
	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify
	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	// Verify BulkSweepMarkers was never called
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_SingleMarkerPerVtxo verifies the typical post-migration
// state where each VTXO has exactly one marker (its own outpoint as the marker ID).
// This represents the common case after the database migration that assigns a unique
// marker to every existing VTXO, ensuring backward compatibility with the new marker system.
func TestCreateCheckpointSweepTask_SingleMarkerPerVtxo(t *testing.T) {
	// Test case: each VTXO has exactly one marker (post-migration state)
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint789"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo789", VOut: 0}

	// Each VTXO has its own unique marker (typical post-migration state)
	childOutpoints := []domain.Outpoint{
		{Txid: "child1", VOut: 0},
		{Txid: "child2", VOut: 0},
	}

	vtxosWithUniqueMarkers := []domain.Vtxo{
		{
			Outpoint:  childOutpoints[0],
			MarkerIDs: []string{"child1:0"}, // Marker ID matches outpoint
			Depth:     0,
		},
		{
			Outpoint:  childOutpoints[1],
			MarkerIDs: []string{"child2:0"},
			Depth:     0,
		},
	}

	toSweep := ports.TxInput{
		Txid:  checkpointTxid,
		Index: 0,
		Value: 20000,
	}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid789", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid789", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosWithUniqueMarkers, nil)

	// Expect exactly 2 unique markers
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.MatchedBy(func(markerIDs []string) bool {
		if len(markerIDs) != 2 {
			return false
		}
		markerSet := make(map[string]bool)
		for _, id := range markerIDs {
			markerSet[id] = true
		}
		return markerSet["child1:0"] && markerSet["child2:0"]
	}), mock.AnythingOfType("int64")).Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	markerRepo.AssertExpectations(t)
}

// TestCreateCheckpointSweepTask_ManyVtxosWithSharedMarkers verifies that the bulk sweep
// optimization works correctly for deep VTXO chains where many VTXOs share the same
// markers. This simulates a chain spanning depths 0-196 where all VTXOs share a root
// marker, and VTXOs at depth >= 100 also share an additional marker. Despite having
// 50 VTXOs, only 2 unique markers should be swept, demonstrating the efficiency gain.
func TestCreateCheckpointSweepTask_ManyVtxosWithSharedMarkers(t *testing.T) {
	// Test case: many VTXOs share markers (chain with depth > 100)
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_deep"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_deep", VOut: 0}

	// Simulate a deep chain where many VTXOs share the same root marker
	childOutpoints := make([]domain.Outpoint, 50)
	vtxosWithSharedMarkers := make([]domain.Vtxo, 50)

	for i := 0; i < 50; i++ {
		childOutpoints[i] = domain.Outpoint{Txid: "child" + string(rune('A'+i)), VOut: 0}
		// All VTXOs at depth < 100 share the root marker
		// VTXOs at depth >= 100 also have a depth-100 marker
		depth := uint32(i * 4) // depths: 0, 4, 8, ... 196 (spans beyond 100)
		markers := []string{"root-marker"}
		if depth >= 100 {
			markers = append(markers, "marker-100")
		}
		vtxosWithSharedMarkers[i] = domain.Vtxo{
			Outpoint:  childOutpoints[i],
			MarkerIDs: markers,
			Depth:     depth,
		}
	}

	toSweep := ports.TxInput{
		Txid:  checkpointTxid,
		Index: 0,
		Value: 500000,
	}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_deep", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_deep", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosWithSharedMarkers, nil)

	// Even with 50 VTXOs, we should only have 2 unique markers
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.MatchedBy(func(markerIDs []string) bool {
		if len(markerIDs) != 2 {
			return false
		}
		markerSet := make(map[string]bool)
		for _, id := range markerIDs {
			markerSet[id] = true
		}
		return markerSet["root-marker"] && markerSet["marker-100"]
	}), mock.AnythingOfType("int64")).Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	markerRepo.AssertExpectations(t)
}

// TestCreateCheckpointSweepTask_SweptAtTimestamp verifies that the sweptAt timestamp
// passed to BulkSweepMarkers is accurate and falls within the execution window.
// This ensures that swept marker records have correct timestamps for auditing and
// debugging purposes, and that the timestamp is generated at execution time rather
// than being a stale or incorrect value.
func TestCreateCheckpointSweepTask_SweptAtTimestamp(t *testing.T) {
	// Test that the sweptAt timestamp is reasonable (within a few seconds of now)
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_timestamp"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_timestamp", VOut: 0}

	childOutpoints := []domain.Outpoint{{Txid: "child_ts", VOut: 0}}
	vtxos := []domain.Vtxo{{
		Outpoint:  childOutpoints[0],
		MarkerIDs: []string{"marker-ts"},
		Depth:     0,
	}}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_ts", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_ts", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxos, nil)

	// Capture the sweptAt timestamp
	beforeExec := time.Now().UnixMilli()
	var capturedSweptAt int64

	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.Anything, mock.MatchedBy(func(sweptAt int64) bool {
		capturedSweptAt = sweptAt
		return true
	})).
		Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()
	afterExec := time.Now().UnixMilli()

	require.NoError(t, err)
	// Verify timestamp is within the execution window
	require.GreaterOrEqual(t, capturedSweptAt, beforeExec)
	require.LessOrEqual(t, capturedSweptAt, afterExec)
}

// TestCreateCheckpointSweepTask_BulkSweepMarkersError verifies that when BulkSweepMarkers
// returns an error, the sweep task propagates the error back to the caller. This ensures
// that marker sweep failures are not silently ignored and can be properly handled by
// the calling code for retry logic or alerting.
func TestCreateCheckpointSweepTask_BulkSweepMarkersError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_error"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_error", VOut: 0}

	childOutpoints := []domain.Outpoint{{Txid: "child_err", VOut: 0}}
	vtxos := []domain.Vtxo{{
		Outpoint:  childOutpoints[0],
		MarkerIDs: []string{"marker-err"},
		Depth:     0,
	}}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_err", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxos, nil)

	// Simulate a database error during bulk sweep
	dbError := fmt.Errorf("database connection failed")
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything).
		Return(dbError)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify the error is propagated
	require.Error(t, err)
	require.Contains(t, err.Error(), "database connection failed")
}

// TestCreateCheckpointSweepTask_GetVtxosError verifies that when GetVtxos fails to
// retrieve the VTXOs associated with child outpoints, the error is properly propagated.
// This tests the error handling path before marker collection even begins.
func TestCreateCheckpointSweepTask_GetVtxosError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_vtxo_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_vtxo_err", VOut: 0}

	childOutpoints := []domain.Outpoint{{Txid: "child_vtxo_err", VOut: 0}}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_vtxo_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_vtxo_err", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	// Simulate error when fetching VTXOs
	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(nil, fmt.Errorf("vtxo not found in database"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify the error is propagated
	require.Error(t, err)
	require.Contains(t, err.Error(), "vtxo not found")

	// BulkSweepMarkers should never be called since we failed earlier
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_GetAllChildrenVtxosError verifies that when
// GetAllChildrenVtxos fails to retrieve child outpoints, the error is propagated.
// This tests the earliest error handling path in the sweep task.
func TestCreateCheckpointSweepTask_GetAllChildrenVtxosError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_children_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_children_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_children_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_children_err", nil)

	// Simulate error when fetching children
	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(nil, fmt.Errorf("failed to query children vtxos"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify the error is propagated
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to query children")

	// Neither GetVtxos nor BulkSweepMarkers should be called
	vtxoRepo.AssertNotCalled(t, "GetVtxos", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_BuildSweepTxError verifies that when BuildSweepTx
// fails to create the sweep transaction, the error is propagated and no marker
// operations are attempted. This tests the very first error handling path.
func TestCreateCheckpointSweepTask_BuildSweepTxError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_build_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_build_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	// Simulate error when building sweep tx
	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("", "", fmt.Errorf("insufficient funds for sweep"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify the error is propagated
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient funds")

	// No other operations should be called
	wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
	vtxoRepo.AssertNotCalled(t, "GetAllChildrenVtxos", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_BroadcastError verifies that when BroadcastTransaction
// fails, the error is propagated and marker sweep operations are not attempted.
// This ensures we don't mark VTXOs as swept if the sweep transaction wasn't actually broadcast.
func TestCreateCheckpointSweepTask_BroadcastError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_broadcast_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_broadcast_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_broadcast_err", "sweeptx_hex", nil)

	// Simulate broadcast failure
	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("", fmt.Errorf("network timeout"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	// Verify the error is propagated
	require.Error(t, err)
	require.Contains(t, err.Error(), "network timeout")

	// Marker operations should not be attempted since broadcast failed
	vtxoRepo.AssertNotCalled(t, "GetAllChildrenVtxos", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_NoChildrenVtxos verifies that when
// GetAllChildrenVtxos returns an empty slice (no children under the unrolled
// vtxo), the sweeper does not attempt to fetch VTXOs or sweep markers.
func TestCreateCheckpointSweepTask_NoChildrenVtxos(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_no_children"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_no_children", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 5000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_nc", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_nc", nil)

	// No children found
	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return([]domain.Outpoint{}, nil)

	// GetVtxos called with empty slice returns empty
	vtxoRepo.On("GetVtxos", mock.Anything, []domain.Outpoint{}).
		Return([]domain.Vtxo{}, nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	// BulkSweepMarkers should NOT be called since there are no VTXOs/markers
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_DuplicateMarkersAcrossVtxos verifies that when
// all VTXOs share the exact same marker set (100% overlap), only the unique
// markers are passed to BulkSweepMarkers. For example, 5 VTXOs each carrying
// {"marker-X", "marker-Y"} should result in exactly 2 markers being swept.
func TestCreateCheckpointSweepTask_DuplicateMarkersAcrossVtxos(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_dup"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_dup", VOut: 0}

	// 5 children, all sharing the identical marker set
	childOutpoints := []domain.Outpoint{
		{Txid: "dup1", VOut: 0},
		{Txid: "dup2", VOut: 0},
		{Txid: "dup3", VOut: 0},
		{Txid: "dup4", VOut: 0},
		{Txid: "dup5", VOut: 0},
	}

	identicalMarkers := []string{"marker-X", "marker-Y"}
	vtxosWithDupMarkers := make([]domain.Vtxo, len(childOutpoints))
	for i, op := range childOutpoints {
		vtxosWithDupMarkers[i] = domain.Vtxo{
			Outpoint:  op,
			MarkerIDs: identicalMarkers,
			Depth:     50,
		}
	}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 25000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_dup", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_dup", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosWithDupMarkers, nil)

	// Despite 5 VTXOs, only 2 unique markers should be swept
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.MatchedBy(func(markerIDs []string) bool {
		if len(markerIDs) != 2 {
			return false
		}
		markerSet := make(map[string]bool)
		for _, id := range markerIDs {
			markerSet[id] = true
		}
		return markerSet["marker-X"] && markerSet["marker-Y"]
	}), mock.AnythingOfType("int64")).Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	markerRepo.AssertExpectations(t)
}

// TestCreateCheckpointSweepTask_LargeMarkerSet verifies that the map-based
// deduplication works correctly at scale: 120 VTXOs carrying a mix of 60
// unique markers. This ensures no scaling issues with the map allocation
// or iteration, and that the deduplicated set is passed correctly to
// BulkSweepMarkers.
func TestCreateCheckpointSweepTask_LargeMarkerSet(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_large"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_large", VOut: 0}

	// 120 VTXOs, each with 2 markers drawn from a pool of 60
	childOutpoints := make([]domain.Outpoint, 120)
	vtxosLarge := make([]domain.Vtxo, 120)
	expectedMarkers := make(map[string]bool)

	for i := range 120 {
		txid := fmt.Sprintf("large-child-%d", i)
		childOutpoints[i] = domain.Outpoint{Txid: txid, VOut: 0}

		// Each VTXO gets two markers: marker-{i%60} and marker-{(i+1)%60}
		m1 := fmt.Sprintf("marker-%d", i%60)
		m2 := fmt.Sprintf("marker-%d", (i+1)%60)
		expectedMarkers[m1] = true
		expectedMarkers[m2] = true

		vtxosLarge[i] = domain.Vtxo{
			Outpoint:  childOutpoints[i],
			MarkerIDs: []string{m1, m2},
			Depth:     uint32(i * 2),
		}
	}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1200000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_large", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_large", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint.Txid).
		Return(childOutpoints, nil)

	vtxoRepo.On("GetVtxos", mock.Anything, childOutpoints).
		Return(vtxosLarge, nil)

	// Should have exactly 60 unique markers (marker-0 through marker-59)
	markerRepo.On("BulkSweepMarkers", mock.Anything, mock.MatchedBy(func(markerIDs []string) bool {
		if len(markerIDs) != 60 {
			return false
		}
		seen := make(map[string]bool)
		for _, id := range markerIDs {
			if seen[id] {
				return false // duplicate found — dedup failed
			}
			seen[id] = true
			if !expectedMarkers[id] {
				return false // unexpected marker
			}
		}
		return true
	}), mock.AnythingOfType("int64")).Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	markerRepo.AssertExpectations(t)
}

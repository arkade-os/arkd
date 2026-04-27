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
func (m *mockWalletService) GetReadyUpdate(ctx context.Context) (<-chan bool, error) {
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
	outpoint domain.Outpoint,
) ([]domain.Outpoint, error) {
	args := m.Called(ctx, outpoint)
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
func (m *mockMarkerRepository) SweepVtxoOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
	sweptAt int64,
) error {
	args := m.Called(ctx, outpoints, sweptAt)
	return args.Error(0)
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
func (m *mockRepoManager) Convictions() domain.ConvictionRepository              { return nil }
func (m *mockRepoManager) Assets() domain.AssetRepository                        { return nil }
func (m *mockRepoManager) Fees() domain.FeeRepository                            { return nil }
func (m *mockRepoManager) RegisterBatchUpdateHandler(func(data domain.Round))    {}
func (m *mockRepoManager) RegisterOffchainTxUpdateHandler(func(domain.OffchainTx)) {}
func (m *mockRepoManager) Close()                                                {}

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

// TestCreateCheckpointSweepTask_SweepsVtxoOutpoints verifies that checkpoint
// sweeps use per-outpoint sweeping (SweepVtxoOutpoints) instead of marker-based
// sweeping. This prevents over-reach when markers are shared across independent
// subtrees due to offchain tx consolidation.
func TestCreateCheckpointSweepTask_SweepsVtxoOutpoints(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint123"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo123", VOut: 0}

	childOutpoints := []domain.Outpoint{
		{Txid: "child1", VOut: 0},
		{Txid: "child2", VOut: 0},
		{Txid: "child3", VOut: 0},
	}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 10000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid123", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid123", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint).
		Return(childOutpoints, nil)

	// SweepVtxoOutpoints should be called with the exact child outpoints
	markerRepo.On("SweepVtxoOutpoints", mock.Anything, childOutpoints, mock.AnythingOfType("int64")).
		Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	markerRepo.AssertExpectations(t)
	builder.AssertExpectations(t)
	// BulkSweepMarkers should NOT be called — checkpoint sweeps use per-outpoint
	markerRepo.AssertNotCalled(t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_SweptAtTimestamp verifies that the sweptAt
// timestamp passed to SweepVtxoOutpoints is accurate.
func TestCreateCheckpointSweepTask_SweptAtTimestamp(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_timestamp"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_timestamp", VOut: 0}

	childOutpoints := []domain.Outpoint{{Txid: "child_ts", VOut: 0}}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_ts", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_ts", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint).
		Return(childOutpoints, nil)

	beforeExec := time.Now().UnixMilli()
	var capturedSweptAt int64

	markerRepo.On("SweepVtxoOutpoints", mock.Anything, childOutpoints, mock.MatchedBy(func(sweptAt int64) bool {
		capturedSweptAt = sweptAt
		return true
	})).Return(nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()
	afterExec := time.Now().UnixMilli()

	require.NoError(t, err)
	require.GreaterOrEqual(t, capturedSweptAt, beforeExec)
	require.LessOrEqual(t, capturedSweptAt, afterExec)
}

// TestCreateCheckpointSweepTask_SweepVtxoOutpointsError verifies error propagation.
func TestCreateCheckpointSweepTask_SweepVtxoOutpointsError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_error"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_error", VOut: 0}

	childOutpoints := []domain.Outpoint{{Txid: "child_err", VOut: 0}}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_err", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint).
		Return(childOutpoints, nil)

	dbError := fmt.Errorf("database connection failed")
	markerRepo.On("SweepVtxoOutpoints", mock.Anything, childOutpoints, mock.AnythingOfType("int64")).
		Return(dbError)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.Error(t, err)
	require.Contains(t, err.Error(), "database connection failed")
}

// TestCreateCheckpointSweepTask_GetAllChildrenVtxosError verifies that when
// GetAllChildrenVtxos fails, the error is propagated.
func TestCreateCheckpointSweepTask_GetAllChildrenVtxosError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_children_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_children_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_children_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_children_err", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint).
		Return(nil, fmt.Errorf("failed to query children vtxos"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to query children")
	markerRepo.AssertNotCalled(t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_BuildSweepTxError verifies that when BuildSweepTx
// fails, no sweep operations are attempted.
func TestCreateCheckpointSweepTask_BuildSweepTxError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_build_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_build_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("", "", fmt.Errorf("insufficient funds for sweep"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient funds")

	wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
	vtxoRepo.AssertNotCalled(t, "GetAllChildrenVtxos", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_BroadcastError verifies that when broadcast
// fails, VTXOs are not marked as swept.
func TestCreateCheckpointSweepTask_BroadcastError(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_broadcast_err"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_broadcast_err", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 1000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_broadcast_err", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("", fmt.Errorf("network timeout"))

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.Error(t, err)
	require.Contains(t, err.Error(), "network timeout")

	vtxoRepo.AssertNotCalled(t, "GetAllChildrenVtxos", mock.Anything, mock.Anything)
	markerRepo.AssertNotCalled(t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything)
}

// TestCreateCheckpointSweepTask_NoChildrenVtxos verifies that an empty
// children list results in no sweep operations.
func TestCreateCheckpointSweepTask_NoChildrenVtxos(t *testing.T) {
	wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper()

	checkpointTxid := "checkpoint_no_children"
	vtxoOutpoint := domain.Outpoint{Txid: "vtxo_no_children", VOut: 0}

	toSweep := ports.TxInput{Txid: checkpointTxid, Index: 0, Value: 5000}

	builder.On("BuildSweepTx", []ports.TxInput{toSweep}).
		Return("sweeptxid_nc", "sweeptx_hex", nil)

	wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptx_hex"}).
		Return("sweeptxid_nc", nil)

	vtxoRepo.On("GetAllChildrenVtxos", mock.Anything, vtxoOutpoint).
		Return([]domain.Outpoint{}, nil)

	task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
	err := task()

	require.NoError(t, err)
	wallet.AssertExpectations(t)
	vtxoRepo.AssertExpectations(t)
	markerRepo.AssertNotCalled(t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything)
}

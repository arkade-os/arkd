package application

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateCheckpointSweepTask(t *testing.T) {
	// checkpoint sweeps use per-outpoint sweeping (SweepVtxoOutpoints) instead of
	// marker-based sweeping. This prevents over-reach when markers are shared
	// across independent subtrees due to offchain tx consolidation.
	t.Run("sweeps vtxo outpoints", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.On(
			"SweepVtxoOutpoints", mock.Anything, childOutpoints, mock.AnythingOfType("int64"),
		).Return(nil)

		task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
		err := task()

		require.NoError(t, err)
		wallet.AssertExpectations(t)
		vtxoRepo.AssertExpectations(t)
		markerRepo.AssertExpectations(t)
		builder.AssertExpectations(t)
		// BulkSweepMarkers should NOT be called — checkpoint sweeps use per-outpoint
		markerRepo.AssertNotCalled(
			t, "BulkSweepMarkers", mock.Anything, mock.Anything, mock.Anything,
		)
	})

	// the sweptAt timestamp passed to SweepVtxoOutpoints is accurate.
	t.Run("sweptAt timestamp", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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

		beforeExec := time.Now().Unix()
		var capturedSweptAt int64

		markerRepo.On(
			"SweepVtxoOutpoints", mock.Anything, childOutpoints,
			mock.MatchedBy(func(sweptAt int64) bool {
				capturedSweptAt = sweptAt
				return true
			}),
		).Return(nil)

		task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
		err := task()
		afterExec := time.Now().Unix()

		require.NoError(t, err)
		require.GreaterOrEqual(t, capturedSweptAt, beforeExec)
		require.LessOrEqual(t, capturedSweptAt, afterExec)
	})

	// error propagation from SweepVtxoOutpoints.
	t.Run("SweepVtxoOutpoints error", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.On(
			"SweepVtxoOutpoints", mock.Anything, childOutpoints, mock.AnythingOfType("int64"),
		).Return(dbError)

		task := s.createCheckpointSweepTask(toSweep, vtxoOutpoint)
		err := task()

		require.Error(t, err)
		require.Contains(t, err.Error(), "database connection failed")
	})

	// when GetAllChildrenVtxos fails, the error is propagated.
	t.Run("GetAllChildrenVtxos error", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.AssertNotCalled(
			t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything,
		)
	})

	// when BuildSweepTx fails, no sweep operations are attempted.
	t.Run("BuildSweepTx error", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.AssertNotCalled(
			t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything,
		)
	})

	// when broadcast fails, VTXOs are not marked as swept.
	t.Run("broadcast error", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.AssertNotCalled(
			t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything,
		)
	})

	// an empty children list results in no sweep operations.
	t.Run("no children vtxos", func(t *testing.T) {
		wallet, vtxoRepo, markerRepo, builder, s := newTestSweeper(t)

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
		markerRepo.AssertNotCalled(
			t, "SweepVtxoOutpoints", mock.Anything, mock.Anything, mock.Anything,
		)
	})
}

// Mock implementations for sweeper tests

type mockWalletService struct {
	mock.Mock
	// isTxConfirmed lets a test drive confirmation state without converting the
	// whole stub to a testify mock.
	isTxConfirmed func(txid string) (bool, *ports.BlockTimestamp, error)
}

func (m *mockWalletService) BroadcastTransaction(
	ctx context.Context, txs ...string,
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
	// A nil network is never valid - callers read network.Name - so return one
	// rather than handing back something that can only panic.
	network := arklib.BitcoinRegTest
	return &network, nil
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
	ctx context.Context, tx string, extractRawTx bool,
) (string, error) {
	return "", nil
}

func (m *mockWalletService) SignTransactionTapscript(
	ctx context.Context, tx string, inputIndexes []int,
) (string, error) {
	return "", nil
}

func (m *mockWalletService) SelectUtxos(
	ctx context.Context, asset string, amount uint64, confirmedOnly bool,
) ([]ports.TxInput, uint64, error) {
	return nil, 0, nil
}
func (m *mockWalletService) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	return 0, nil
}
func (m *mockWalletService) FeeRate(ctx context.Context) (uint64, error) { return 0, nil }

func (m *mockWalletService) ListConnectorUtxos(
	ctx context.Context, addrs []string,
) ([]ports.TxInput, error) {
	return nil, nil
}
func (m *mockWalletService) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return 0, 0, nil
}
func (m *mockWalletService) GetMainAccountUtxos(ctx context.Context) ([]ports.WalletUtxo, error) {
	return nil, nil
}
func (m *mockWalletService) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return 0, 0, nil
}
func (m *mockWalletService) LockConnectorUtxos(ctx context.Context, utxos []domain.Outpoint) error {
	return nil
}
func (m *mockWalletService) GetDustAmount(ctx context.Context) (uint64, error) { return 0, nil }

func (m *mockWalletService) GetOutpointStatus(
	ctx context.Context, outpoint domain.Outpoint,
) (bool, error) {
	return false, nil
}

func (m *mockWalletService) GetCurrentBlockTime(
	ctx context.Context,
) (*ports.BlockTimestamp, error) {
	return nil, nil
}

func (m *mockWalletService) Withdraw(
	ctx context.Context, address string, amount uint64, all bool,
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
	ctx context.Context, txid string,
) (bool, *ports.BlockTimestamp, error) {
	if m.isTxConfirmed != nil {
		return m.isTxConfirmed(txid)
	}
	return false, nil, nil
}
func (m *mockWalletService) RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error {
	return nil
}

type mockVtxoRepository struct {
	mock.Mock
	onUpdateExpiration func(outpoints []domain.Outpoint, expiresAt int64)
}

func (m *mockVtxoRepository) GetAllChildrenVtxos(
	ctx context.Context, outpoint domain.Outpoint,
) ([]domain.Outpoint, error) {
	args := m.Called(ctx, outpoint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Outpoint), args.Error(1)
}

func (m *mockVtxoRepository) GetVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	args := m.Called(ctx, outpoints)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Vtxo), args.Error(1)
}

// Stub implementations for unused VtxoRepository methods
func (m *mockVtxoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	return nil
}

func (m *mockVtxoRepository) GetCheckpointTxsByVtxoPubKeys(
	ctx context.Context, pubkeys []string,
) ([]domain.Tx, error) {
	return nil, nil
}

func (m *mockVtxoRepository) SettleVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, commitmentTxid string,
) error {
	return nil
}

func (m *mockVtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, arkTxid string,
) error {
	return nil
}
func (m *mockVtxoRepository) UnrollVtxos(ctx context.Context, outpoints []domain.Outpoint) error {
	return nil
}

func (m *mockVtxoRepository) GetAllNonUnrolledVtxos(
	ctx context.Context, pubkey string,
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
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetExpiringLiquidity(
	ctx context.Context, after, before int64,
) (uint64, error) {
	return 0, nil
}
func (m *mockVtxoRepository) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (m *mockVtxoRepository) UpdateVtxosExpiration(
	ctx context.Context, outpoints []domain.Outpoint, expiresAt int64,
) error {
	if m.onUpdateExpiration != nil {
		m.onUpdateExpiration(outpoints, expiresAt)
	}
	return nil
}

func (m *mockVtxoRepository) GetLeafVtxosForBatch(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context, commitmentTxid string,
) ([]domain.Outpoint, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetVtxoPubKeysByCommitmentTxid(
	ctx context.Context, commitmentTxid string, withMinimumAmount uint64,
) ([]string, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetVtxoPubKeysByCommitmentTxids(
	ctx context.Context, commitmentTxids []string, withMinimumAmount uint64,
) ([]string, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetPendingSpentVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockVtxoRepository) Close() {}

type mockMarkerRepository struct {
	mock.Mock
}

func (m *mockMarkerRepository) BulkSweepMarkers(
	ctx context.Context, markerIDs []string, sweptAt int64,
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

func (m *mockMarkerRepository) GetMarkersByDepthRange(
	ctx context.Context, minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetMarkersByIds(
	ctx context.Context, ids []string,
) ([]domain.Marker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	return false, nil
}

func (m *mockMarkerRepository) GetSweptMarkers(
	ctx context.Context, markerIDs []string,
) ([]domain.SweptMarker, error) {
	return nil, nil
}

func (m *mockMarkerRepository) UpdateVtxoMarkers(
	ctx context.Context, outpoint domain.Outpoint, markerIDs []string,
) error {
	return nil
}

func (m *mockMarkerRepository) GetVtxosByMarker(
	ctx context.Context, markerID string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) CreateRootMarkersForVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) error {
	return nil
}

func (m *mockMarkerRepository) GetVtxosByDepthRange(
	ctx context.Context, minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetVtxosByArkTxid(
	ctx context.Context, arkTxid string,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockMarkerRepository) GetVtxoChainByMarkers(
	ctx context.Context, markerIDs []string,
) ([]domain.Vtxo, error) {
	return nil, nil
}
func (m *mockMarkerRepository) SweepVtxoOutpoints(
	ctx context.Context, outpoints []domain.Outpoint, sweptAt int64,
) error {
	args := m.Called(ctx, outpoints, sweptAt)
	return args.Error(0)
}

func (m *mockMarkerRepository) Close() {}

type mockTxBuilder struct {
	mock.Mock
	sweepableBatchOutputs func(*tree.TxTree) (*tree.SweepParams, *ports.TxInput, error)
}

func (m *mockTxBuilder) BuildSweepTx(inputs []ports.TxInput) (string, string, error) {
	args := m.Called(inputs)
	return args.String(0), args.String(1), args.Error(2)
}

// Stub implementations for unused TxBuilder methods
func (m *mockTxBuilder) BuildCommitmentTx(
	signerPubkey *btcec.PublicKey, intents domain.Intents,
	boardingInputs []ports.BoardingInput, cosigners [][]string,
	sweepParams tree.SweepParams,
) (string, *tree.TxTree, string, *tree.TxTree, error) {
	return "", nil, "", nil, nil
}

func (m *mockTxBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo, connectors tree.FlatTxTree, txs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	return nil, nil
}

func (m *mockTxBuilder) GetSweepableBatchOutputs(
	vtxoTree *tree.TxTree,
) (*tree.SweepParams, *ports.TxInput, error) {
	if m.sweepableBatchOutputs != nil {
		return m.sweepableBatchOutputs(vtxoTree)
	}
	return nil, nil, nil
}
func (m *mockTxBuilder) FinalizeAndExtract(tx string) (string, error) { return "", nil }

func (m *mockTxBuilder) VerifyVtxoTapscriptSigs(
	tx string, mustIncludeSignerSig bool,
) (bool, *psbt.Packet, error) {
	return false, nil, nil
}

func (m *mockTxBuilder) VerifyBoardingTapscriptSigs(
	signedTx string, commitmentTx string,
) (map[uint32]ports.SignedBoardingInput, error) {
	return nil, nil
}

type mockRepoManager struct {
	vtxos   *mockVtxoRepository
	markers *mockMarkerRepository
	rounds  domain.RoundRepository
}

func (m *mockRepoManager) Events() domain.EventRepository {
	return nil
}
func (m *mockRepoManager) Rounds() domain.RoundRepository {
	return m.rounds
}
func (m *mockRepoManager) Vtxos() domain.VtxoRepository {
	return m.vtxos
}
func (m *mockRepoManager) Markers() domain.MarkerRepository {
	return m.markers
}
func (m *mockRepoManager) OffchainTxs() domain.OffchainTxRepository {
	return nil
}
func (m *mockRepoManager) Convictions() domain.ConvictionRepository {
	return nil
}
func (m *mockRepoManager) Assets() domain.AssetRepository {
	return nil
}
func (m *mockRepoManager) Settings() domain.SettingsRepository {
	return nil
}
func (m *mockRepoManager) RegisterBatchUpdateHandler(func(data domain.Round))            {}
func (m *mockRepoManager) RegisterOffchainTxUpdateHandler(func(domain.OffchainTx))       {}
func (m *mockRepoManager) RegisterSettingsUpdateHandler(func(domain.Settings, []string)) {}
func (m *mockRepoManager) Close()                                                        {}

type mockScheduler struct{}

func (m *mockScheduler) Start()                                       {}
func (m *mockScheduler) Stop()                                        {}
func (m *mockScheduler) Unit() ports.TimeUnit                         { return ports.UnixTime }
func (m *mockScheduler) AfterNow(expiry int64) bool                   { return false }
func (m *mockScheduler) ScheduleTaskOnce(at int64, task func()) error { return nil }

// newTestSweeper creates a fresh set of mocks and a sweeper instance for testing.
func newTestSweeper(t *testing.T) (
	*mockWalletService,
	*mockVtxoRepository,
	*mockMarkerRepository,
	*mockTxBuilder,
	*sweeper,
) {
	t.Helper()
	wallet := &mockWalletService{}
	vtxoRepo := &mockVtxoRepository{}
	markerRepo := &mockMarkerRepository{}
	repoManager := &mockRepoManager{vtxos: vtxoRepo, markers: markerRepo}
	builder := &mockTxBuilder{}
	scheduler := &mockScheduler{}
	s := newSweeper(wallet, repoManager, builder, scheduler)
	return wallet, vtxoRepo, markerRepo, builder, s
}

// controllableScheduler captures the scheduled closure so a test can fire it on
// demand. mockScheduler above is a no-op and cannot drive scheduleTask.
type controllableScheduler struct {
	fn func()
}

func (s *controllableScheduler) Start()               {}
func (s *controllableScheduler) Stop()                {}
func (s *controllableScheduler) Unit() ports.TimeUnit { return ports.UnixTime }
func (s *controllableScheduler) AfterNow(expiry int64) bool {
	return true // always "in the future" so scheduleTask registers rather than running inline
}
func (s *controllableScheduler) ScheduleTaskOnce(at int64, task func()) error {
	s.fn = task
	return nil
}
func (s *controllableScheduler) fire() {
	if s.fn != nil {
		s.fn()
	}
}

// newSchedulableSweeper builds a sweeper wired to a scheduler the test controls.
// newTestSweeper above uses mockScheduler, whose ScheduleTaskOnce is a no-op.
func newSchedulableSweeper(sched ports.SchedulerService, attempts int) *sweeper {
	s := newSweeper(&mockWalletService{}, &mockRepoManager{}, &mockTxBuilder{}, sched)
	s.ctx = context.Background()
	// per-instance, so shrinking the policy cannot race another test
	s.retryDelay = time.Millisecond
	s.retryAttempts = attempts
	return s
}

// TestScheduleTaskRetriesFailedExecution pins that a sweep whose broadcast fails
// is re-attempted rather than silently dropped. Before this, a single mempool
// conflict left the batch unswept until an operator restart.
func TestScheduleTaskRetriesFailedExecution(t *testing.T) {
	sched := &controllableScheduler{}
	s := newSchedulableSweeper(sched, 3)

	calls := 0
	require.NoError(t, s.scheduleTask(sweeperTask{
		id: "task-fail",
		at: time.Now().Add(time.Hour).Unix(),
		execute: func() error {
			calls++
			return fmt.Errorf("broadcast rejected")
		},
	}))

	sched.fire()

	// one initial attempt plus sweepRetryAttempts retries
	require.Equal(t, 1+3, calls, "a failed sweep must be retried, not dropped")
}

// TestScheduleTaskStopsRetryingOnSuccess pins that a retry that succeeds ends the
// loop instead of burning the remaining attempts.
func TestScheduleTaskStopsRetryingOnSuccess(t *testing.T) {
	sched := &controllableScheduler{}
	s := newSchedulableSweeper(sched, 5)

	calls := 0
	require.NoError(t, s.scheduleTask(sweeperTask{
		id: "task-eventually-ok",
		at: time.Now().Add(time.Hour).Unix(),
		execute: func() error {
			calls++
			if calls < 3 {
				return fmt.Errorf("still conflicting")
			}
			return nil
		},
	}))

	sched.fire()
	require.Equal(t, 3, calls, "retrying must stop as soon as the sweep succeeds")
}

// TestScheduleTaskFreesDedupSlot pins that the id is released once the task has
// run, so a later schedule for the same tree is accepted. scheduledTasks is a
// dedup guard: holding the id past execution would block re-scheduling entirely.
func TestScheduleTaskFreesDedupSlot(t *testing.T) {
	sched := &controllableScheduler{}
	s := newSchedulableSweeper(sched, 1)

	at := time.Now().Add(time.Hour).Unix()
	failing := sweeperTask{
		id: "task-slot", at: at,
		execute: func() error { return fmt.Errorf("broadcast rejected") },
	}
	require.NoError(t, s.scheduleTask(failing))

	s.locker.Lock()
	_, registered := s.scheduledTasks["task-slot"]
	s.locker.Unlock()
	require.True(t, registered, "task must occupy the dedup slot while pending")

	sched.fire()

	s.locker.Lock()
	_, stillHeld := s.scheduledTasks["task-slot"]
	s.locker.Unlock()
	require.False(t, stillHeld, "dedup slot must be released so the id can be re-scheduled")

	second := 0
	require.NoError(t, s.scheduleTask(sweeperTask{
		id: "task-slot", at: at,
		execute: func() error { second++; return nil },
	}))
	sched.fire()
	require.Equal(t, 1, second, "a fresh schedule for the same id must be accepted")
}

// TestScheduleTaskRetriesAlreadyDueTask covers the path a restart takes. When a
// batch expired while the service was down, AfterNow is false and scheduleTask
// runs the task inline rather than handing it to the scheduler. That path must
// use the same bounded retry policy - it is the case that most needs it, since
// nothing will re-arm the task until the next restart.
func TestScheduleTaskRetriesAlreadyDueTask(t *testing.T) {
	sched := &immediateScheduler{}
	s := newSchedulableSweeper(sched, 3)

	calls := 0
	err := s.scheduleTask(sweeperTask{
		id: "already-due",
		at: time.Now().Add(-time.Hour).Unix(),
		execute: func() error {
			calls++
			return fmt.Errorf("broadcast rejected")
		},
	})

	require.Error(t, err, "the final failure must still reach the caller")
	require.Equal(t, 1+3, calls, "an already-due task must retry like a scheduled one")
}

// immediateScheduler reports every task as already due, which is what a restart
// looks like for a batch that expired while the service was down.
type immediateScheduler struct{}

func (s *immediateScheduler) Start()                               {}
func (s *immediateScheduler) Stop()                                {}
func (s *immediateScheduler) Unit() ports.TimeUnit                 { return ports.UnixTime }
func (s *immediateScheduler) AfterNow(expiry int64) bool           { return false }
func (s *immediateScheduler) ScheduleTaskOnce(int64, func()) error { return nil }

// recordingScheduler records what each task was scheduled for, so a test can
// assert on the time rather than only on the fact that something was scheduled.
type recordingScheduler struct {
	mu   sync.Mutex
	at   []int64
	unit ports.TimeUnit
	now  int64
}

func (s *recordingScheduler) Start() {}
func (s *recordingScheduler) Stop()  {}
func (s *recordingScheduler) Unit() ports.TimeUnit {
	if s.unit == 0 {
		return ports.UnixTime
	}
	return s.unit
}
func (s *recordingScheduler) AfterNow(expiry int64) bool { return expiry > s.now }
func (s *recordingScheduler) ScheduleTaskOnce(at int64, task func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.at = append(s.at, at)
	return nil
}
func (s *recordingScheduler) scheduled() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.at...)
}

// TestBatchSweepTaskSchedulesEpochBatchAtItsDate covers the path every restart
// takes: sweeper.start runs the batch sweep task immediately for each live
// batch, finds the batch output is not yet mature, and reschedules it.
//
// The reschedule used to derive its own time instead of reusing the maturity
// findSweepableOutputs had just computed, reading the relative psbt field as a
// tree expiry. For an epoch batch that field carries the unroll grace, so the
// sweep was scheduled a grace period after the commitment confirmed - hours
// rather than weeks - and the same wrong value was written onto every leaf
// vtxo's expiry.
func TestBatchSweepTaskSchedulesEpochBatchAtItsDate(t *testing.T) {
	const (
		commitmentTxid = "0000000000000000000000000000000000000000000000000000000000000abc"
		graceSeconds   = 7168 // ~2h, the unroll grace an epoch tree carries in field 3
	)

	now := time.Now().Unix()
	commitmentConfirmedAt := now - 60
	// The epoch date: weeks out, nothing like commitmentConfirmedAt+grace.
	epochDate := arklib.AbsoluteLocktime(now + 21*24*3600)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: graceSeconds}

	flatTree, rootTxid := buildEpochTestTree(t, commitmentTxid, epochDate, grace)

	sched := &recordingScheduler{now: now}
	wallet := &mockWalletService{}
	vtxoRepo := &mockVtxoRepository{}
	builder := &mockTxBuilder{}
	rounds := &mockedRoundRepo{}
	rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).Return(flatTree, nil)

	repoManager := &mockRepoManager{
		vtxos: vtxoRepo, markers: &mockMarkerRepository{}, rounds: rounds,
	}
	s := newSweeper(wallet, repoManager, builder, sched)

	// The batch root is unconfirmed; the commitment above it is confirmed. That is
	// what an untouched, still-live batch looks like.
	wallet.isTxConfirmed = func(txid string) (bool, *ports.BlockTimestamp, error) {
		if txid == commitmentTxid {
			return true, &ports.BlockTimestamp{Time: commitmentConfirmedAt, Height: 100}, nil
		}
		return false, &ports.BlockTimestamp{}, nil
	}

	builder.sweepableBatchOutputs = func(
		*tree.TxTree,
	) (*tree.SweepParams, *ports.TxInput, error) {
		date := epochDate
		return &tree.SweepParams{Expiry: grace, BatchExpiry: &date},
			&ports.TxInput{Txid: commitmentTxid, Index: 0, Value: 10000}, nil
	}

	var expiryWrites []int64
	vtxoRepo.onUpdateExpiration = func(_ []domain.Outpoint, expiresAt int64) {
		expiryWrites = append(expiryWrites, expiresAt)
	}

	require.NoError(t, s.createBatchSweepTask(commitmentTxid, rootTxid)())

	// Scheduling is synchronous, so this returns on the first check. The bounded
	// wait is here so a regression that schedules asynchronously still reports the
	// wrong time rather than an empty slice.
	deadline := time.Now().Add(2 * time.Second)
	for len(sched.scheduled()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	wrong := commitmentConfirmedAt + graceSeconds
	scheduled := sched.scheduled()
	require.NotEmpty(t, scheduled, "the batch sweep must be rescheduled, not dropped")
	for _, at := range scheduled {
		require.NotEqual(t, wrong, at, "scheduled at commitment+grace instead of the epoch date")
		require.Equal(t, int64(epochDate), at, "an epoch batch must sweep at its epoch date")
	}

	require.NotEmpty(t, expiryWrites, "leaf vtxo expiries must be updated")
	for _, at := range expiryWrites {
		require.Equal(
			t, int64(epochDate), at,
			"leaf vtxos must carry the epoch date, not commitment+grace",
		)
	}
}

// buildEpochTestTree returns a two-node tree whose root spends the commitment's
// batch output and carries the epoch psbt fields, plus the root txid.
func buildEpochTestTree(
	t *testing.T, commitmentTxid string, date arklib.AbsoluteLocktime,
	grace arklib.RelativeLocktime,
) (tree.FlatTxTree, string) {
	t.Helper()

	commitmentHash, err := chainhash.NewHashFromStr(commitmentTxid)
	require.NoError(t, err)

	rootPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *commitmentHash, Index: 0}},
		[]*wire.TxOut{{Value: 10000, PkScript: append([]byte{0x51, 0x20}, make([]byte, 32)...)}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	require.NoError(t, txutils.SetArkPsbtField(
		rootPtx, 0, txutils.VtxoTreeExpiryField, grace,
	))
	require.NoError(t, txutils.SetArkPsbtField(
		rootPtx, 0, txutils.BatchExpiryField, date,
	))
	rootTxid := rootPtx.UnsignedTx.TxID()
	rootB64, err := rootPtx.B64Encode()
	require.NoError(t, err)

	rootHash, err := chainhash.NewHashFromStr(rootTxid)
	require.NoError(t, err)
	leafScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	leafScript[2] = 0x01
	leafPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *rootHash, Index: 0}},
		[]*wire.TxOut{{Value: 10000, PkScript: leafScript}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	leafTxid := leafPtx.UnsignedTx.TxID()
	leafB64, err := leafPtx.B64Encode()
	require.NoError(t, err)

	return tree.FlatTxTree{
		{Txid: rootTxid, Tx: rootB64, Children: map[uint32]string{0: leafTxid}},
		{Txid: leafTxid, Tx: leafB64, Children: nil},
	}, rootTxid
}

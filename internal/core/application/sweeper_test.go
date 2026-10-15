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
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
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

func TestCreateBatchSweepTask(t *testing.T) {
	const commitmentTxid = "1111111111111111111111111111111111111111111111111111111111111111"

	// a two-leaf tree whose confirmed root exposes two expired batch outputs, one per leaf
	splitTree := func(t *testing.T, f *batchSweepFixture) (
		string, string, string, ports.TxInput, ports.TxInput,
	) {
		t.Helper()
		rootTxid, rootTx := sweepTestTx(t, commitmentTxid, 0, 2)
		aTxid, aTx := sweepTestTx(t, rootTxid, 0, 1)
		bTxid, bTx := sweepTestTx(t, rootTxid, 1, 1)
		flatTree := tree.FlatTxTree{
			{Txid: rootTxid, Tx: rootTx, Children: map[uint32]string{0: aTxid, 1: bTxid}},
			{Txid: aTxid, Tx: aTx},
			{Txid: bTxid, Tx: bTx},
		}
		outA := ports.TxInput{Txid: rootTxid, Index: 0, Value: 10000}
		outB := ports.TxInput{Txid: rootTxid, Index: 1, Value: 20000}

		f.rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).Return(flatTree, nil)
		f.rounds.On("GetRoundWithCommitmentTxid", mock.Anything, commitmentTxid).
			Return(sweepableRound(commitmentTxid, flatTree), nil).Maybe()
		f.wallet.On("IsTransactionConfirmed", mock.Anything, rootTxid).
			Return(true, &ports.BlockTimestamp{Height: 100, Time: 1700000000}, nil)

		for _, leaf := range []struct {
			batch ports.TxInput
			txid  string
		}{{outA, aTxid}, {outB, bTxid}} {
			batch := leaf.batch
			f.wallet.On("IsTransactionConfirmed", mock.Anything, leaf.txid).
				Return(false, nil, nil)
			f.builder.On("GetSweepableBatchOutputs", matchSubTree(leaf.txid)).
				Return(&arklib.RelativeLocktime{Value: 512}, &batch, nil)
			f.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{
				{Txid: batch.Txid, VOut: batch.Index},
			}).Return([]domain.Vtxo{}, nil)
			f.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: leaf.txid}}).
				Return([]domain.Vtxo{{Outpoint: domain.Outpoint{Txid: leaf.txid}}}, nil)
			f.vtxos.On("GetAllChildrenVtxos", mock.Anything, domain.Outpoint{Txid: leaf.txid}).
				Return([]domain.Outpoint{}, nil).Maybe()
		}

		return rootTxid, aTxid, bTxid, outA, outB
	}

	// a one-leaf tree whose expired batch output is the commitment output itself. The caller
	// registers IsTransactionConfirmed for the tree tx, so it can control its cardinality.
	singleTree := func(t *testing.T, f *batchSweepFixture) (string, string) {
		t.Helper()
		rootTxid, rootTx := sweepTestTx(t, commitmentTxid, 0, 1)
		leafTxid, leafTx := sweepTestTx(t, rootTxid, 0, 1)
		flatTree := tree.FlatTxTree{
			{Txid: rootTxid, Tx: rootTx, Children: map[uint32]string{0: leafTxid}},
			{Txid: leafTxid, Tx: leafTx},
		}
		batchOutput := ports.TxInput{Txid: commitmentTxid, Index: 0, Value: 10000}

		f.rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).Return(flatTree, nil)
		f.rounds.On("GetRoundWithCommitmentTxid", mock.Anything, commitmentTxid).
			Return(sweepableRound(commitmentTxid, flatTree), nil).Maybe()
		f.wallet.On("IsTransactionConfirmed", mock.Anything, commitmentTxid).
			Return(true, &ports.BlockTimestamp{Height: 100, Time: 1700000000}, nil)
		f.builder.On("GetSweepableBatchOutputs", matchSubTree(rootTxid)).
			Return(&arklib.RelativeLocktime{Value: 512}, &batchOutput, nil)
		f.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: commitmentTxid}}).
			Return([]domain.Vtxo{}, nil)
		f.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: leafTxid}}).
			Return([]domain.Vtxo{{Outpoint: domain.Outpoint{Txid: leafTxid}}}, nil)
		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{Txid: commitmentTxid}).
			Return(true, nil)

		return rootTxid, leafTxid
	}

	// the batch output is spent by a tree tx sitting in the mempool: that is its owner
	// unrolling, not a sweep, so no vtxo may be recorded as swept
	t.Run("batch output spent by a tree tx", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, _ := singleTree(t, f)

		f.wallet.On("IsTransactionConfirmed", mock.Anything, rootTxid).Return(false, nil, nil)
		// unconfirmed, but the wallet knows it: the tree tx is in the mempool
		f.wallet.On("GetTransaction", mock.Anything, rootTxid).Return("treetxhex", nil)
		// only reached if the task records a sweep it never made
		f.builder.On("BuildSweepTx", mock.Anything).
			Return("sweeptxid", "sweeptxhex", nil).Maybe()

		require.NoError(t, f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)())
		require.Empty(t, batchSweptEvents(t, f))
	})

	// nothing explains the spend, so it counts as a sweep an earlier run failed to record
	t.Run("tree tx unknown to the wallet", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, leafTxid := singleTree(t, f)

		f.wallet.On("IsTransactionConfirmed", mock.Anything, rootTxid).Return(false, nil, nil)
		f.wallet.On("GetTransaction", mock.Anything, rootTxid).
			Return("", fmt.Errorf("transaction not found"))
		f.builder.On("BuildSweepTx", []ports.TxInput{
			{Txid: commitmentTxid, Index: 0, Value: 10000},
		}).Return("sweeptxid", "sweeptxhex", nil)

		require.NoError(t, f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)())

		events := batchSweptEvents(t, f)
		require.Len(t, events, 1)
		require.Equal(t, []domain.Outpoint{{Txid: leafTxid}}, events[0].LeafVtxos)
		f.wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
	})

	// a tree tx lookup that fails for another reason than the tx being unknown tells nothing
	// about who spent the output: the task must fail and be retried instead of recording a sweep
	t.Run("tree tx lookup error fails the task", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, _ := singleTree(t, f)

		f.wallet.On("IsTransactionConfirmed", mock.Anything, rootTxid).Return(false, nil, nil)
		f.wallet.On("GetTransaction", mock.Anything, rootTxid).
			Return("", fmt.Errorf("context deadline exceeded"))
		f.builder.On("BuildSweepTx", mock.Anything).
			Return("sweeptxid", "sweeptxhex", nil).Maybe()

		err := f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)()
		require.ErrorContains(t, err, "context deadline exceeded")
		require.Empty(t, batchSweptEvents(t, f))
	})

	// a failed status query leaves the task unable to tell what it swept: it must fail and be
	// retried instead of recording the outputs it did check
	t.Run("outpoint status error fails the task", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, _, _, outA, outB := splitTree(t, f)

		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outA.Txid, VOut: outA.Index,
		}).Return(false, fmt.Errorf("indexer unreachable"))
		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outB.Txid, VOut: outB.Index,
		}).Return(false, nil).Maybe()
		f.builder.On("BuildSweepTx", mock.Anything).
			Return("sweeptxid", "sweeptxhex", nil).Maybe()
		f.wallet.On("GetTransaction", mock.Anything, mock.Anything).Return("", nil).Maybe()
		f.wallet.On("BroadcastTransaction", mock.Anything, mock.Anything).
			Return("sweeptxid", nil).Maybe()

		err := f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)()
		require.ErrorContains(t, err, "indexer unreachable")
		require.Empty(t, batchSweptEvents(t, f))
	})

	t.Run("sweeps every unspent output", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, aTxid, bTxid, _, _ := splitTree(t, f)

		f.wallet.On("GetOutpointStatus", mock.Anything, mock.Anything).Return(false, nil)
		f.builder.On("BuildSweepTx", mock.MatchedBy(func(ins []ports.TxInput) bool {
			return len(ins) == 2
		})).Return("sweeptxid", "sweeptxhex", nil)
		f.wallet.On("GetTransaction", mock.Anything, "sweeptxid").Return("", nil)
		f.wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptxhex"}).
			Return("sweeptxid", nil)

		require.NoError(t, f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)())

		events := batchSweptEvents(t, f)
		require.Len(t, events, 1)
		require.Equal(t, "sweeptxid", events[0].Txid)
		require.ElementsMatch(
			t, []domain.Outpoint{{Txid: aTxid}, {Txid: bTxid}}, events[0].LeafVtxos,
		)
	})

	// the sweep tx covers the unspent output only, so the event covers its leaves only
	t.Run("leaves of a spent output are left alone", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, aTxid, bTxid, outA, outB := splitTree(t, f)

		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outA.Txid, VOut: outA.Index,
		}).Return(true, nil)
		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outB.Txid, VOut: outB.Index,
		}).Return(false, nil)
		f.wallet.On("GetTransaction", mock.Anything, aTxid).Return("treetxhex", nil)
		f.builder.On("BuildSweepTx", []ports.TxInput{outB}).
			Return("sweeptxid", "sweeptxhex", nil)
		f.wallet.On("GetTransaction", mock.Anything, "sweeptxid").Return("", nil)
		f.wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptxhex"}).
			Return("sweeptxid", nil)

		require.NoError(t, f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)())

		events := batchSweptEvents(t, f)
		require.Len(t, events, 1)
		require.Equal(t, []domain.Outpoint{{Txid: bTxid}}, events[0].LeafVtxos)
		f.vtxos.AssertNotCalled(
			t, "GetAllChildrenVtxos", mock.Anything, domain.Outpoint{Txid: aTxid},
		)
	})

	// the sweep tx covers the unspent output, the event covers both
	t.Run("sweeps one output and records an unrecorded sweep of the other", func(t *testing.T) {
		f := newBatchSweepFixture(t)
		rootTxid, aTxid, bTxid, outA, outB := splitTree(t, f)

		f.wallet.On("IsTransactionConfirmed", mock.Anything, aTxid).Return(false, nil, nil)
		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outA.Txid, VOut: outA.Index,
		}).Return(true, nil)
		f.wallet.On("GetOutpointStatus", mock.Anything, domain.Outpoint{
			Txid: outB.Txid, VOut: outB.Index,
		}).Return(false, nil)
		f.wallet.On("GetTransaction", mock.Anything, aTxid).
			Return("", fmt.Errorf("transaction not found"))
		f.builder.On("BuildSweepTx", []ports.TxInput{outB}).
			Return("sweeptxid", "sweeptxhex", nil)
		f.wallet.On("GetTransaction", mock.Anything, "sweeptxid").Return("", nil)
		f.wallet.On("BroadcastTransaction", mock.Anything, []string{"sweeptxhex"}).
			Return("sweeptxid", nil)

		require.NoError(t, f.sweeper.createBatchSweepTask(commitmentTxid, rootTxid)())

		events := batchSweptEvents(t, f)
		require.Len(t, events, 1)
		require.ElementsMatch(
			t, []domain.Outpoint{{Txid: aTxid}, {Txid: bTxid}}, events[0].LeafVtxos,
		)
	})
}

// Mock implementations for sweeper tests

type mockWalletService struct {
	mock.Mock
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
	args := m.Called(ctx, outpoint)
	return args.Bool(0), args.Error(1)
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
) <-chan ports.TxNotification {
	return nil
}

func (m *mockWalletService) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (bool, *ports.BlockTimestamp, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(1); v != nil {
		return args.Bool(0), v.(*ports.BlockTimestamp), args.Error(2)
	}
	return args.Bool(0), nil, args.Error(2)
}
func (m *mockWalletService) RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error {
	return nil
}

type mockVtxoRepository struct {
	mock.Mock
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

func (m *mockVtxoRepository) GetSweepableVtxosByCommitmentTxids(
	context.Context, []string,
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

func (m *mockVtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	return nil, nil
}

func (m *mockVtxoRepository) GetVtxosWithPubKeys(
	ctx context.Context, filter domain.VtxoFilter, page domain.Page,
) ([]domain.Vtxo, int32, error) {
	return nil, 0, nil
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
}

func (m *mockTxBuilder) BuildSweepTx(inputs []ports.TxInput) (string, string, error) {
	args := m.Called(inputs)
	return args.String(0), args.String(1), args.Error(2)
}

// Stub implementations for unused TxBuilder methods
func (m *mockTxBuilder) BuildCommitmentTx(
	signerPubkey *btcec.PublicKey, intents domain.Intents,
	boardingInputs []ports.BoardingInput, cosigners [][]string,
	vtxoTreeExpiry arklib.RelativeLocktime,
) (string, *tree.TxTree, string, *tree.TxTree, error) {
	return "", nil, "", nil, nil
}

func (m *mockTxBuilder) VerifyAndRebuildForfeitTxs(
	vtxos []domain.Vtxo, connectors tree.FlatTxTree, txs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	return nil, nil
}

func (m *mockTxBuilder) GetSweepableBatchOutputs(
	vtxoTree *tree.TxTree,
) (*arklib.RelativeLocktime, *ports.TxInput, error) {
	args := m.Called(vtxoTree)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*arklib.RelativeLocktime), args.Get(1).(*ports.TxInput), args.Error(2)
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
	events  domain.EventRepository
}

func (m *mockRepoManager) Events() domain.EventRepository {
	return m.events
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
func (m *mockRepoManager) CosignedUtxos() domain.UtxoRepository {
	return nil
}
func (m *mockRepoManager) Reconcile() error {
	return nil
}
func (m *mockRepoManager) RegisterBatchUpdateHandler(func(data domain.Round))            {}
func (m *mockRepoManager) RegisterOffchainTxUpdateHandler(func(domain.OffchainTx))       {}
func (m *mockRepoManager) RegisterOnchainTxUpdateHandler(func(domain.OnchainTx))         {}
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

type batchSweepFixture struct {
	wallet  *mockWalletService
	vtxos   *mockVtxoRepository
	rounds  *mockedRoundRepo
	events  *fakeEventRepo
	builder *mockTxBuilder
	sweeper *sweeper
}

func newBatchSweepFixture(t *testing.T) *batchSweepFixture {
	t.Helper()
	wallet := &mockWalletService{}
	vtxos := &mockVtxoRepository{}
	rounds := &mockedRoundRepo{}
	events := newFakeEventRepo(t, nil)
	builder := &mockTxBuilder{}
	s := newSweeper(wallet, &mockRepoManager{
		vtxos: vtxos, markers: &mockMarkerRepository{}, rounds: rounds, events: events,
	}, builder, &mockScheduler{})
	s.ctx = t.Context()
	return &batchSweepFixture{wallet, vtxos, rounds, events, builder, s}
}

// sweepTestTx builds a tx spending the given outpoint, with as many non-anchor outputs as
// asked for, and returns its txid and base64 PSBT.
func sweepTestTx(t *testing.T, prevTxid string, prevIndex uint32, outputs int) (string, string) {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(prevTxid)
	require.NoError(t, err)

	scripts := make([][]byte, 0, outputs)
	for i := 0; i < outputs; i++ {
		pkScript := make([]byte, 34)
		pkScript[0], pkScript[1] = 0x51, 0x20
		pkScript[2], pkScript[3] = byte(prevIndex+1), byte(i+1)
		scripts = append(scripts, pkScript)
	}

	tx := newTestTx([]wire.OutPoint{{Hash: *hash, Index: prevIndex}}, scripts)
	return tx.TxID(), mustEncodePSBTB64(t, tx)
}

func sweepableRound(commitmentTxid string, vtxoTree tree.FlatTxTree) *domain.Round {
	return &domain.Round{
		Id:             "round-id",
		CommitmentTxid: commitmentTxid,
		Stage:          domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		VtxoTree:       vtxoTree,
	}
}

// matchSubTree matches the sub tree rooted at the given txid.
func matchSubTree(txid string) any {
	return mock.MatchedBy(func(subTree *tree.TxTree) bool {
		return subTree.Root.UnsignedTx.TxID() == txid
	})
}

func batchSweptEvents(t *testing.T, f *batchSweepFixture) []domain.BatchSwept {
	t.Helper()
	swept := make([]domain.BatchSwept, 0)
	for _, event := range f.events.saved[domain.RoundTopic+":round-id"] {
		if e, ok := event.(domain.BatchSwept); ok {
			swept = append(swept, e)
		}
	}
	return swept
}

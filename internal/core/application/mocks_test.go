package application

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
)

type mockedRoundRepo struct {
	mock.Mock
	domain.RoundRepository // unimplemented methods panic on call
}

func (m *mockedRoundRepo) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	args := m.Called(ctx, txids)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundVtxoTree(ctx context.Context, txid string) (arktree.FlatTxTree, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(0); v != nil {
		return v.(arktree.FlatTxTree), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetSweepableRounds(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

type mockedVtxoRepo struct {
	mock.Mock
	domain.VtxoRepository // unimplemented methods panic on call
}

func (m *mockedVtxoRepo) GetVtxos(ctx context.Context, outpoints []domain.Outpoint) ([]domain.Vtxo, error) {
	args := m.Called(ctx, outpoints)
	if v := args.Get(0); v != nil {
		return v.([]domain.Vtxo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedVtxoRepo) GetAllVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	args := m.Called(ctx, pubkeys, after, before)
	if v := args.Get(0); v != nil {
		return v.([]domain.Vtxo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedVtxoRepo) GetVtxoPubKeysByCommitmentTxids(
	ctx context.Context, commitmentTxids []string, withMinimumAmount uint64,
) ([]string, error) {
	args := m.Called(ctx, commitmentTxids, withMinimumAmount)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedVtxoRepo) GetCheckpointTxsByVtxoPubKeys(
	ctx context.Context, pubkeys []string,
) ([]domain.Tx, error) {
	args := m.Called(ctx, pubkeys)
	if v := args.Get(0); v != nil {
		return v.([]domain.Tx), args.Error(1)
	}
	return nil, args.Error(1)
}

type mockedRepoManager struct {
	mock.Mock
	ports.RepoManager // unimplemented methods panic on call
	// offchainTxHandler captures the handler registered via
	// RegisterOffchainTxUpdateHandler so tests can dispatch it directly
	// to exercise the inline closure in registerEventHandlers.
	offchainTxHandler func(domain.OffchainTx)
}

func (m *mockedRepoManager) Rounds() domain.RoundRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.RoundRepository)
	}
	return nil
}

func (m *mockedRepoManager) Vtxos() domain.VtxoRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.VtxoRepository)
	}
	return nil
}

func (m *mockedRepoManager) Markers() domain.MarkerRepository {
	return nil
}

func (m *mockedRepoManager) OffchainTxs() domain.OffchainTxRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.OffchainTxRepository)
	}
	return nil
}

func (m *mockedRepoManager) RegisterOffchainTxUpdateHandler(h func(domain.OffchainTx)) {
	m.offchainTxHandler = h
}

func (m *mockedRepoManager) RegisterBatchUpdateHandler(func(domain.Round)) {}

func (m *mockedRepoManager) RegisterSettingsUpdateHandler(func(domain.Settings, []string)) {
}

type mockedOffchainTxRepo struct {
	mock.Mock
	domain.OffchainTxRepository // unimplemented methods panic on call
}

func (m *mockedOffchainTxRepo) GetOffchainTx(ctx context.Context, txid string) (*domain.OffchainTx, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(0); v != nil {
		return v.(*domain.OffchainTx), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedOffchainTxRepo) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	args := m.Called(ctx, txids)
	if v := args.Get(0); v != nil {
		return v.([]*domain.OffchainTx), args.Error(1)
	}
	return nil, args.Error(1)
}

type mockedWallet struct {
	mock.Mock
	ports.WalletService // unimplemented methods panic on call
}

func (m *mockedWallet) GetTransaction(ctx context.Context, txid string) (string, error) {
	args := m.Called(ctx, txid)
	return args.String(0), args.Error(1)
}

func (m *mockedWallet) GetDustAmount(ctx context.Context) (uint64, error) {
	args := m.Called(ctx)
	return args.Get(0).(uint64), args.Error(1)
}

// mockedScanner records every WatchScripts/UnwatchScripts payload across
// calls so restore/stop tests can assert the full set of scripts handed to
// the scanner, not just the args of one call.
type mockedScanner struct {
	mock.Mock
	watched   []string
	unwatched []string
	mu        sync.Mutex
}

func (m *mockedScanner) WatchScripts(
	ctx context.Context, scripts []string,
) error {
	m.mu.Lock()
	m.watched = append(m.watched, scripts...)
	m.mu.Unlock()
	return m.Called(ctx, scripts).Error(0)
}

func (m *mockedScanner) UnwatchScripts(
	ctx context.Context, scripts []string,
) error {
	m.mu.Lock()
	m.unwatched = append(m.unwatched, scripts...)
	m.mu.Unlock()
	return m.Called(ctx, scripts).Error(0)
}

// Watched returns a copy of all scripts handed to WatchScripts across calls,
// synchronized so tests that poll via require.Eventually do not race with
// the goroutines the production code launches.
func (m *mockedScanner) Watched() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.watched...)
}

// Unwatched is the UnwatchScripts counterpart of Watched.
func (m *mockedScanner) Unwatched() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.unwatched...)
}

func (m *mockedScanner) GetNotificationChannel(
	_ context.Context,
) <-chan map[string][]ports.VtxoWithValue {
	return nil
}

func (m *mockedScanner) IsTransactionConfirmed(
	_ context.Context, _ string,
) (bool, *ports.BlockTimestamp, error) {
	return false, nil, nil
}

func (m *mockedScanner) RescanUtxos(_ context.Context, _ []wire.OutPoint) error {
	return nil
}

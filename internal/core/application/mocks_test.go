package application

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/wire/v2"
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

func (m *mockedRoundRepo) GetExpiredButNotSweptRounds(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundWithCommitmentTxid(
	ctx context.Context, txid string,
) (*domain.Round, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(0); v != nil {
		return v.(*domain.Round), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundsWithCommitmentTxids(
	ctx context.Context, txids []string,
) (map[string]any, error) {
	args := m.Called(ctx, txids)
	if v := args.Get(0); v != nil {
		return v.(map[string]any), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	return m.Called(ctx, round).Error(0)
}

func (m *mockedRoundRepo) SweepRounds(ctx context.Context, commitmentTxids []string) error {
	return m.Called(ctx, commitmentTxids).Error(0)
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

// GetVtxosWithPubKeys filters and pages the stubbed set like the real
// stores do. PendingOnly needs a lookup of the spending tx that the stub
// cannot express, so it is refused rather than matching everything and
// letting a test pass vacuously; the db tests cover it.
func (m *mockedVtxoRepo) GetVtxosWithPubKeys(
	ctx context.Context, filter domain.VtxoFilter, page domain.Page,
) ([]domain.Vtxo, int32, error) {
	if filter.PendingOnly {
		return nil, 0, fmt.Errorf("mockedVtxoRepo: PendingOnly is not modelled, use the db tests")
	}

	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, 0, args.Error(1)
	}

	matched := make([]domain.Vtxo, 0)
	for _, vtxo := range args.Get(0).([]domain.Vtxo) {
		if matchesFilter(filter, vtxo) {
			matched = append(matched, vtxo)
		}
	}
	sortByCreatedAt(matched)

	total := int32(len(matched))
	if page.Offset >= total {
		return nil, total, args.Error(1)
	}
	end := total
	if page.Limit > 0 {
		end = min(page.Offset+page.Limit, total)
	}

	return matched[page.Offset:end], total, args.Error(1)
}

func (m *mockedVtxoRepo) GetVtxosWithAssets(
	ctx context.Context, filter domain.VtxoFilter, page domain.Page,
) ([]domain.Vtxo, int32, error) {
	args := m.Called(ctx, filter, page)
	return args.Get(0).([]domain.Vtxo), args.Get(1).(int32), args.Error(2)
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
	// Capture registered handlers so tests can exercise the callbacks directly.
	batchHandler      func(domain.Round)
	offchainTxHandler func(domain.OffchainTx)
	onchainTxHandler  func(domain.OnchainTx)
	// utxos and events are served as is, not through expectations, so concurrent tests can
	// hit them.
	utxos  domain.UtxoRepository
	events domain.EventRepository
}

func (m *mockedRepoManager) CosignedUtxos() domain.UtxoRepository {
	return m.utxos
}

func (m *mockedRepoManager) Events() domain.EventRepository {
	if m.events != nil {
		return m.events
	}
	return m.RepoManager.Events()
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

func (m *mockedRepoManager) Convictions() domain.ConvictionRepository {
	if v := m.Called().Get(0); v != nil {
		return v.(domain.ConvictionRepository)
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

func (m *mockedRepoManager) RegisterBatchUpdateHandler(h func(domain.Round)) {
	m.batchHandler = h
}

func (m *mockedRepoManager) RegisterOnchainTxUpdateHandler(h func(domain.OnchainTx)) {
	m.onchainTxHandler = h
}

func (m *mockedRepoManager) Close() {
	m.Called()
}

func (m *mockedRepoManager) RegisterSettingsUpdateHandler(func(domain.Settings, []string)) {
}

type mockedEventRepo struct {
	mock.Mock
	domain.EventRepository // unimplemented methods panic on call
}

func (m *mockedEventRepo) Save(
	ctx context.Context, topic, id string, events []domain.Event,
) error {
	return m.Called(ctx, topic, id, events).Error(0)
}

type mockedOffchainTxStore struct {
	mock.Mock
	ports.OffChainTxStore // unimplemented methods panic on call
}

func (m *mockedOffchainTxStore) Get(ctx context.Context, txid string) (*domain.OffchainTx, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(0); v != nil {
		return v.(*domain.OffchainTx), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedOffchainTxStore) LockFinalization(
	ctx context.Context, txid string, ttl time.Duration,
) error {
	return m.Called(ctx, txid, ttl).Error(0)
}

func (m *mockedOffchainTxStore) UnlockFinalization(ctx context.Context, txid string) error {
	return m.Called(ctx, txid).Error(0)
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

func (m *mockedWallet) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (bool, *ports.BlockTimestamp, error) {
	args := m.Called(ctx, txid)
	if v := args.Get(1); v != nil {
		return args.Bool(0), v.(*ports.BlockTimestamp), args.Error(2)
	}
	return args.Bool(0), nil, args.Error(2)
}

func (m *mockedWallet) GetOutpointStatus(
	ctx context.Context, outpoint domain.Outpoint,
) (bool, error) {
	args := m.Called(ctx, outpoint)
	return args.Bool(0), args.Error(1)
}

func (m *mockedWallet) GetCurrentBlockTime(ctx context.Context) (*ports.BlockTimestamp, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.(*ports.BlockTimestamp), args.Error(1)
	}
	return nil, args.Error(1)
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
) <-chan ports.TxNotification {
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

func matchesFilter(f domain.VtxoFilter, v domain.Vtxo) bool {
	switch {
	case f.SpendableOnly:
		return !v.Spent && !v.Swept && !v.Unrolled
	case f.SpentOnly:
		return v.Spent || v.Swept || v.Unrolled
	case f.RenewableOnly:
		return !v.Spent && !v.Unrolled
	case f.RecoverableOnly:
		return !v.Spent && !v.Unrolled && (v.Swept || v.IsNote())
	}
	return true
}

func sortByCreatedAt(vtxos []domain.Vtxo) {
	sort.SliceStable(vtxos, func(i, j int) bool {
		if vtxos[i].CreatedAt != vtxos[j].CreatedAt {
			return vtxos[i].CreatedAt > vtxos[j].CreatedAt
		}
		if vtxos[i].Txid != vtxos[j].Txid {
			return vtxos[i].Txid < vtxos[j].Txid
		}
		return vtxos[i].VOut < vtxos[j].VOut
	})
}

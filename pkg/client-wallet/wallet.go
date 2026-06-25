package wallet

import (
	"context"
	"fmt"
	"sync"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	storetypes "github.com/arkade-os/arkd/pkg/client-wallet/types"
	types "github.com/arkade-os/arkd/pkg/client-wallet/types"
	log "github.com/sirupsen/logrus"
)

const (
	// identity
	SingleKeyIdentity = clientlib.SingleKeyIdentity
	// store
	InMemoryStore = types.InMemoryStore
	FileStore     = types.FileStore
)

var (
	ErrAlreadyInitialized = fmt.Errorf("wallet already initialized")
	ErrNotInitialized     = fmt.Errorf("wallet not initialized")
	ErrIsLocked           = fmt.Errorf("wallet is locked")

	supportedIdentities = supportedType[struct{}]{
		SingleKeyIdentity: struct{}{},
	}
)

type wallet struct {
	*storetypes.Config
	identity clientlib.Identity
	store    types.Store
	explorer clientlib.Explorer
	client   clientlib.Client
	indexer  clientlib.Indexer

	txLock                 *sync.RWMutex
	verbose                bool
	withFinalizePendingTxs bool
	clientVersion          string
}

func NewWallet(storeSvc types.Store, opts ...WalletOption) (Wallet, error) {
	if storeSvc == nil {
		return nil, fmt.Errorf("missing store")
	}

	cfgData, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	wallet := &wallet{
		store:                  storeSvc,
		txLock:                 &sync.RWMutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(wallet)
	}

	if wallet.identity == nil {
		storeType := storeSvc.GetType()
		datadir := storeSvc.GetDatadir()
		identitySvc, err := getSingleKeyIdentity(datadir, storeType)
		if err != nil {
			return nil, fmt.Errorf("failed to setup identity: %s", err)
		}
		wallet.identity = identitySvc
	}

	return wallet, nil
}

func LoadWallet(storeSvc types.Store, opts ...WalletOption) (Wallet, error) {
	if storeSvc == nil {
		return nil, fmt.Errorf("missing sdk repository")
	}

	cfgData, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	wallet := &wallet{
		Config:                 cfgData,
		store:                  storeSvc,
		txLock:                 &sync.RWMutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(wallet)
	}

	if wallet.identity == nil {
		storeType := storeSvc.GetType()
		datadir := storeSvc.GetDatadir()
		identitySvc, err := getSingleKeyIdentity(datadir, storeType)
		if err != nil {
			return nil, fmt.Errorf("failed to setup identity: %s", err)
		}
		wallet.identity = identitySvc
	}

	if wallet.explorer == nil {
		explorerOpts := []explorer.Option{explorer.WithTracker(false)}
		explorerSvc, err := explorer.NewExplorer(
			cfgData.ExplorerURL, cfgData.Network, explorerOpts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to setup explorer: %s", err)
		}
		wallet.explorer = explorerSvc
	}

	clientSvc, err := client.NewClient(cfgData.ServerUrl, wallet.clientVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}
	indexerSvc, err := indexer.NewClient(cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	wallet.client = clientSvc
	wallet.indexer = indexerSvc

	return wallet, nil
}

func (w *wallet) Identity() clientlib.Identity {
	return w.identity
}

func (w *wallet) Client() clientlib.Client {
	return w.client
}

func (w *wallet) Indexer() clientlib.Indexer {
	return w.indexer
}

func (w *wallet) Explorer() clientlib.Explorer {
	return w.explorer
}

func (w *wallet) GetVersion() string {
	return Version
}

func (w *wallet) GetConfigData(_ context.Context) (*storetypes.Config, error) {
	if w.Config == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return w.Config, nil
}

func (w *wallet) Unlock(ctx context.Context, password string) error {
	if _, err := w.identity.Unlock(ctx, password); err != nil {
		return err
	}

	log.SetLevel(log.DebugLevel)
	if !w.verbose {
		log.SetLevel(log.WarnLevel)
	}

	if w.withFinalizePendingTxs {
		txids, err := w.FinalizePendingTxs(ctx, nil)
		if err != nil {
			return err
		}
		switch len(txids) {
		case 0:
			log.Debug("no pending txs to finalize")
		case 1:
			log.Debug("finalized 1 pending tx")
		default:
			log.Debugf("finalized %d pending txs", len(txids))
		}
	}

	return nil
}

func (w *wallet) Lock(ctx context.Context) error {
	if w.identity == nil {
		return ErrNotInitialized
	}
	return w.identity.Lock(ctx)
}

func (w *wallet) IsLocked(ctx context.Context) bool {
	if w.identity == nil {
		return true
	}
	return w.identity.IsLocked()
}

func (w *wallet) Dump(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}
	return w.identity.Dump(ctx)
}

func (w *wallet) Reset(ctx context.Context) {
	if w.client != nil {
		w.client.Close()
	}
	if w.indexer != nil {
		w.indexer.Close()
	}

	if w.store != nil {
		w.store.Clean(ctx)
	}
}

func (w *wallet) Stop() {
	if w.client != nil {
		w.client.Close()
	}
	if w.indexer != nil {
		w.indexer.Close()
	}

	if w.store != nil {
		w.store.Close()
	}
}

func (w *wallet) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	return w.identity.SignTransaction(ctx, tx, nil)
}

func (w *wallet) safeCheck() error {
	if w.identity == nil {
		return ErrNotInitialized
	}
	if w.identity.IsLocked() {
		return ErrIsLocked
	}
	return nil
}

type getVtxosFilter struct {
	// If specified, returns only vtxos matching given outpoints
	outpoints []clientlib.Outpoint
	// If true, excludes recoverable vtxos from the list
	excludeRecoverableVtxos bool
	// If true, excludes vtxos holding assets from the list
	excludeAssetVtxos bool
}

func (w *wallet) getSpendableVtxos(
	ctx context.Context, opts *getVtxosFilter,
) ([]clientlib.Vtxo, error) {
	vtxos, _, err := w.getVtxos(ctx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.outpoints) > 0 {
		vtxos = filterByOutpoints(vtxos, opts.outpoints)
	}

	if opts != nil && opts.excludeRecoverableVtxos {
		filteredVtxos := make([]clientlib.Vtxo, 0, len(vtxos))
		for _, vtxo := range vtxos {
			if vtxo.IsRecoverable() {
				continue
			}
			filteredVtxos = append(filteredVtxos, vtxo)
		}
		vtxos = filteredVtxos
	}

	if opts != nil && opts.excludeAssetVtxos {
		filteredVtxos := make([]clientlib.Vtxo, 0, len(vtxos))
		for _, vtxo := range vtxos {
			if len(vtxo.Assets) > 0 {
				continue
			}
			filteredVtxos = append(filteredVtxos, vtxo)
		}
		vtxos = filteredVtxos
	}

	return vtxos, nil
}

func (w *wallet) getPendingVtxos(
	ctx context.Context, createdAfter *time.Time,
) ([]clientlib.Vtxo, error) {
	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	_, vtxos, err := w.getVtxos(ctx, clientlib.WithPendingOnly())
	if err != nil {
		return nil, err
	}

	if createdAfter != nil {
		filtered := make([]clientlib.Vtxo, 0, len(vtxos))
		for _, vtxo := range vtxos {
			if !createdAfter.IsZero() {
				if !vtxo.CreatedAt.After(*createdAfter) {
					continue
				}
			}
			filtered = append(filtered, vtxo)
		}
		vtxos = filtered
	}

	vtxos, _, err = w.populateVtxosWithTapscripts(ctx, vtxos, nil, offchainAddr, nil)
	return vtxos, err
}

func (w *wallet) getVtxos(
	ctx context.Context, opts ...clientlib.GetVtxosOption,
) ([]clientlib.Vtxo, []clientlib.Vtxo, error) {
	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, nil, err
	}

	script, err := offchainAddr.Script()
	if err != nil {
		return nil, nil, err
	}

	scripts := []string{script}
	opts = append(opts, clientlib.WithScripts(scripts))
	resp, err := w.indexer.GetVtxos(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}

	spendableVtxos := make([]clientlib.Vtxo, 0, len(resp.Vtxos))
	spentVtxos := make([]clientlib.Vtxo, 0, len(resp.Vtxos))
	for _, vtxo := range resp.Vtxos {
		if vtxo.Spent || vtxo.Unrolled {
			spentVtxos = append(spentVtxos, vtxo)
			continue
		}

		if vtxo.IsRecoverable() {
			spendableVtxos = append(spendableVtxos, vtxo)
			continue
		}

		spendableVtxos = append(spendableVtxos, vtxo)
	}

	spendableVtxos, _, err = w.populateVtxosWithTapscripts(
		ctx, spendableVtxos, nil, offchainAddr, nil,
	)
	if err != nil {
		return nil, nil, err
	}
	return spendableVtxos, spentVtxos, nil
}

func (w *wallet) populateVtxosWithTapscripts(
	ctx context.Context, vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo,
	offchainAddr, boardingAddr *clientlib.Address,
) ([]clientlib.Vtxo, []clientlib.Utxo, error) {
	var vtxosWithSignInfo []clientlib.Vtxo
	if len(vtxos) > 0 {
		vtxosWithSignInfo = make([]clientlib.Vtxo, len(vtxos))
		copy(vtxosWithSignInfo, vtxos)
		vtxoSigningClosure, err := offchainAddr.CollaborativeClosure()
		if err != nil {
			return nil, nil, err
		}
		for i := range vtxosWithSignInfo {
			vtxosWithSignInfo[i].Tapscripts = offchainAddr.Tapscripts
			vtxosWithSignInfo[i].SigningClosure = vtxoSigningClosure
		}
	}

	var utxosWithSignInfo []clientlib.Utxo
	if len(boardingUtxos) > 0 {
		utxosWithSignInfo = make([]clientlib.Utxo, len(boardingUtxos))
		copy(utxosWithSignInfo, boardingUtxos)
		utxoSigningClosure, err := boardingAddr.CollaborativeClosure()
		if err != nil {
			return nil, nil, err
		}

		for i := range utxosWithSignInfo {
			utxosWithSignInfo[i].Tapscripts = boardingAddr.Tapscripts
			utxosWithSignInfo[i].SigningClosure = utxoSigningClosure
		}
	}

	return vtxosWithSignInfo, utxosWithSignInfo, nil
}

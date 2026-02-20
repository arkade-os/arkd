package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	log "github.com/sirupsen/logrus"
)

const (
	// wallet
	SingleKeyWallet = wallet.SingleKeyWallet
	// store
	FileStore     = types.FileStore
	InMemoryStore = types.InMemoryStore
	// explorer
	BitcoinExplorer = mempool_explorer.BitcoinExplorer
)

var (
	ErrAlreadyInitialized = fmt.Errorf("client already initialized")
	ErrNotInitialized     = fmt.Errorf("client not initialized")

	supportedWallets = utils.SupportedType[struct{}]{
		SingleKeyWallet: struct{}{},
	}
)

type service struct {
	*types.Config
	wallet   wallet.WalletService
	store    types.Store
	explorer explorer.Explorer
	client   client.TransportClient
	indexer  indexer.Indexer

	txLock                 *sync.RWMutex
	verbose                bool
	withMonitorConn        bool
	withFinalizePendingTxs bool
}

func NewArkClient(storeSvc types.Store, opts ...ServiceOption) (ArkClient, error) {
	cfgData, err := storeSvc.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	client := &service{
		store:                  storeSvc,
		txLock:                 &sync.RWMutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func LoadArkClient(storeSvc types.Store, opts ...ServiceOption) (ArkClient, error) {
	if storeSvc == nil {
		return nil, fmt.Errorf("missing sdk repository")
	}

	cfgData, err := storeSvc.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	walletSvc, err := getWallet(storeSvc.ConfigStore(), cfgData.WalletType, supportedWallets)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wallet: %s", err)
	}

	client := &service{
		Config:                 cfgData,
		wallet:                 walletSvc,
		store:                  storeSvc,
		txLock:                 &sync.RWMutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	if client.explorer == nil {
		explorerOpts := []mempool_explorer.Option{mempool_explorer.WithTracker(false)}
		explorerSvc, err := mempool_explorer.NewExplorer(
			cfgData.ExplorerURL, cfgData.Network, explorerOpts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to setup explorer: %s", err)
		}
		client.explorer = explorerSvc
	}

	clientSvc, err := grpcclient.NewClient(cfgData.ServerUrl, client.withMonitorConn)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}
	indexerSvc, err := grpcindexer.NewClient(cfgData.ServerUrl, client.withMonitorConn)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	client.client = clientSvc
	client.indexer = indexerSvc

	return client, nil
}

func LoadArkClientWithWallet(
	sdkStore types.Store, walletSvc wallet.WalletService, opts ...ServiceOption,
) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missin sdk repository")
	}

	if walletSvc == nil {
		return nil, fmt.Errorf("missin wallet service")
	}

	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	client := &service{
		Config:                 cfgData,
		wallet:                 walletSvc,
		store:                  sdkStore,
		txLock:                 &sync.RWMutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	if client.explorer == nil {
		explorerOpts := []mempool_explorer.Option{
			mempool_explorer.WithTracker(false),
		}
		explorerSvc, err := mempool_explorer.NewExplorer(
			cfgData.ExplorerURL, cfgData.Network, explorerOpts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to setup explorer: %s", err)
		}
		client.explorer = explorerSvc
	}

	clientSvc, err := grpcclient.NewClient(cfgData.ServerUrl, client.withMonitorConn)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}
	indexerSvc, err := grpcindexer.NewClient(cfgData.ServerUrl, client.withMonitorConn)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	client.client = clientSvc
	client.indexer = indexerSvc

	return client, nil
}

func (a *service) GetVersion() string {
	return Version
}

func (a *service) GetConfigData(_ context.Context) (*types.Config, error) {
	if a.Config == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.Config, nil
}

func (a *service) Unlock(ctx context.Context, password string) error {
	if _, err := a.wallet.Unlock(ctx, password); err != nil {
		return err
	}

	log.SetLevel(log.DebugLevel)
	if !a.verbose {
		log.SetLevel(log.WarnLevel)
	}

	if a.withFinalizePendingTxs {
		txids, err := a.finalizePendingTxs(ctx, nil)
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

func (a *service) Lock(ctx context.Context) error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	return a.wallet.Lock(ctx)
}

func (a *service) IsLocked(ctx context.Context) bool {
	if a.wallet == nil {
		return true
	}
	return a.wallet.IsLocked()
}

func (a *service) Dump(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	return a.wallet.Dump(ctx)
}

func (a *service) Reset(ctx context.Context) {
	a.client.Close()
	a.indexer.Close()

	if a.store != nil {
		a.store.Clean(ctx)
	}
}

func (a *service) Stop() {
	a.client.Close()
	a.indexer.Close()

	if a.store != nil {
		a.store.Close()
	}
}

func (a *service) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	return a.wallet.SignTransaction(ctx, a.explorer, tx)
}

func (a *service) safeCheck() error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}
	return nil
}

func (a *service) getVtxos(
	ctx context.Context,
) (spendableVtxos, spentVtxos []types.Vtxo, err error) {
	if a.wallet == nil {
		return nil, nil, ErrNotInitialized
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return
	}

	scripts := make([]string, 0, len(offchainAddrs))
	for _, addr := range offchainAddrs {
		decoded, err := arklib.DecodeAddressV0(addr.Address)
		if err != nil {
			return nil, nil, err
		}
		vtxoScript, err := script.P2TRScript(decoded.VtxoTapKey)
		if err != nil {
			return nil, nil, err
		}
		scripts = append(scripts, hex.EncodeToString(vtxoScript))
	}
	opt := indexer.GetVtxosRequestOption{}
	if err = opt.WithScripts(scripts); err != nil {
		return
	}

	resp, err := a.indexer.GetVtxos(ctx, opt)
	if err != nil {
		return nil, nil, err
	}

	for _, vtxo := range resp.Vtxos {
		if vtxo.IsRecoverable() {
			spendableVtxos = append(spendableVtxos, vtxo)
			continue
		}

		if vtxo.Spent || vtxo.Unrolled {
			spentVtxos = append(spentVtxos, vtxo)
			continue
		}

		spendableVtxos = append(spendableVtxos, vtxo)
	}
	return
}

func (a *service) getSpendableVtxos(
	ctx context.Context, opts *getVtxosFilter,
) ([]types.Vtxo, error) {
	spendable, _, err := a.getVtxos(ctx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.outpoints) > 0 {
		spendable = filterByOutpoints(spendable, opts.outpoints)
	}

	recoverableVtxos := make([]types.Vtxo, 0)
	spendableVtxos := make([]types.Vtxo, 0, len(spendable))
	if opts != nil && opts.withRecoverableVtxos {
		for _, vtxo := range spendable {
			if vtxo.IsRecoverable() {
				recoverableVtxos = append(recoverableVtxos, vtxo)
				continue
			}
			spendableVtxos = append(spendableVtxos, vtxo)
		}
	} else {
		spendableVtxos = make([]types.Vtxo, len(spendable))
		copy(spendableVtxos, spendable)
	}

	allVtxos := append(recoverableVtxos, spendableVtxos...)

	if opts != nil && opts.recomputeExpiry {
		// if sorting by expiry is required, we need to get the expiration date of each vtxo
		redeemBranches, err := a.getRedeemBranches(ctx, spendableVtxos)
		if err != nil {
			return nil, err
		}

		for vtxoTxid, branch := range redeemBranches {
			expiration, err := branch.ExpiresAt()
			if err != nil {
				return nil, err
			}

			for i, vtxo := range allVtxos {
				if vtxo.Txid == vtxoTxid {
					allVtxos[i].ExpiresAt = *expiration
					break
				}
			}
		}
	}

	if opts != nil && opts.expiryThreshold > 0 {
		allVtxos = utils.FilterVtxosByExpiry(allVtxos, opts.expiryThreshold)
	}

	if opts == nil || !opts.withoutExpirySorting {
		allVtxos = utils.SortVtxosByExpiry(allVtxos)
	}

	if opts != nil && opts.excludeAssetVtxos {
		filteredVtxos := make([]types.Vtxo, 0, len(allVtxos))
		for _, vtxo := range allVtxos {
			if len(vtxo.Assets) == 0 {
				filteredVtxos = append(filteredVtxos, vtxo)
			}
		}
		allVtxos = filteredVtxos
	}

	return allVtxos, nil
}

func (a *service) fetchPendingSpentVtxos(ctx context.Context) ([]types.Vtxo, error) {
	if a.wallet == nil {
		return nil, ErrNotInitialized
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	scripts := make([]string, 0, len(offchainAddrs))
	for _, addr := range offchainAddrs {
		decoded, err := arklib.DecodeAddressV0(addr.Address)
		if err != nil {
			return nil, err
		}
		vtxoScript, err := script.P2TRScript(decoded.VtxoTapKey)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, hex.EncodeToString(vtxoScript))
	}
	opt := indexer.GetVtxosRequestOption{}
	opt.WithPendingOnly()
	if err = opt.WithScripts(scripts); err != nil {
		return nil, err
	}
	resp, err := a.indexer.GetVtxos(ctx, opt)
	if err != nil {
		return nil, err
	}
	return resp.Vtxos, nil
}

func (a *service) populateVtxosWithTapscripts(
	ctx context.Context, vtxos []types.Vtxo,
) ([]types.VtxoWithTapTree, error) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, fmt.Errorf("no offchain addresses found")
	}

	vtxosWithTapscripts := make([]types.VtxoWithTapTree, 0)

	for _, v := range vtxos {
		found := false
		for _, offchainAddr := range offchainAddrs {
			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return nil, err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxosWithTapscripts = append(vtxosWithTapscripts, types.VtxoWithTapTree{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no offchain address found for vtxo %s", v.Txid)
		}
	}

	return vtxosWithTapscripts, nil
}

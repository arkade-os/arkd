package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	restindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/rest"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	filestore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	log "github.com/sirupsen/logrus"
)

const (
	// transport
	GrpcClient = client.GrpcClient
	RestClient = client.RestClient
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
)

type ClientOption func(*arkClient)

func WithVerbose() ClientOption {
	return func(c *arkClient) {
		c.verbose = true
	}
}

// WithRefreshDb enables periodic refresh of the db when WithTransactionFeed is set
func WithRefreshDb(interval time.Duration) ClientOption {
	return func(c *arkClient) {
		if interval > 0 {
			c.refreshDbInterval = interval
		}
	}
}

func WithoutFinalizePendingTxs() ClientOption {
	return func(c *arkClient) {
		c.withFinalizePendingTxs = false
	}
}

type arkClient struct {
	*types.Config
	wallet   wallet.WalletService
	store    types.Store
	explorer explorer.Explorer
	client   client.TransportClient
	indexer  indexer.Indexer

	syncMu *sync.Mutex
	// TODO drop the channel
	syncCh            chan error
	syncDone          bool
	syncErr           error
	syncListeners     *syncListeners
	stopFn            context.CancelFunc
	refreshDbInterval time.Duration
	dbMu              *sync.Mutex

	utxoBroadcaster *utils.Broadcaster[types.UtxoEvent]
	vtxoBroadcaster *utils.Broadcaster[types.VtxoEvent]
	txBroadcaster   *utils.Broadcaster[types.TransactionEvent]

	verbose                bool
	withFinalizePendingTxs bool
}

func (a *arkClient) GetVersion() string {
	return Version
}

func (a *arkClient) GetConfigData(_ context.Context) (*types.Config, error) {
	if a.Config == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.Config, nil
}

func (a *arkClient) Unlock(ctx context.Context, password string) error {
	cfgData, err := a.GetConfigData(ctx)
	if err != nil {
		return err
	}

	if _, err := a.wallet.Unlock(ctx, password); err != nil {
		return err
	}

	log.SetLevel(log.DebugLevel)
	if !a.verbose {
		log.SetLevel(log.ErrorLevel)
	}

	a.dbMu = &sync.Mutex{}

	if cfgData.WithTransactionFeed {
		a.syncDone = false
		a.syncErr = nil
		a.syncCh = make(chan error)
		a.syncMu = &sync.Mutex{}
		a.utxoBroadcaster = utils.NewBroadcaster[types.UtxoEvent]()
		a.vtxoBroadcaster = utils.NewBroadcaster[types.VtxoEvent]()
		a.txBroadcaster = utils.NewBroadcaster[types.TransactionEvent]()

		go func() {
			err := <-a.syncCh
			a.setRestored(err)
		}()

		go func() {
			a.explorer.Start()

			ctx, cancel := context.WithCancel(context.Background())
			a.stopFn = cancel

			err := func() error {
				if err := a.refreshDb(ctx); err != nil {
					return err
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
			}()
			a.syncCh <- err
			close(a.syncCh)

			// start listening to stream events
			go a.listenForArkTxs(ctx)
			go a.listenForOnchainTxs(ctx)
			go a.listenDbEvents(ctx)

			// start periodic refresh db
			go a.periodicRefreshDb(ctx)
		}()
	}

	return nil
}

func (a *arkClient) Lock(ctx context.Context) error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	if err := a.wallet.Lock(ctx); err != nil {
		return err
	}
	go func() {
		a.explorer.Stop()
		if a.WithTransactionFeed {
			a.syncMu.Lock()
			a.syncDone = false
			a.syncErr = nil
			a.syncMu.Unlock()
		}
		if a.stopFn != nil {
			a.stopFn()
		}
		if a.syncListeners != nil {
			a.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
			a.syncListeners.clear()
		}
	}()
	return nil
}

func (a *arkClient) IsLocked(ctx context.Context) bool {
	if a.wallet == nil {
		return true
	}
	return a.wallet.IsLocked()
}

func (a *arkClient) Dump(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	return a.wallet.Dump(ctx)
}

func (a *arkClient) Receive(ctx context.Context) (string, string, string, error) {
	if a.wallet == nil {
		return "", "", "", fmt.Errorf("wallet not initialized")
	}

	onchainAddr, offchainAddr, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", "", err
	}

	if a.UtxoMaxAmount == 0 {
		boardingAddr.Address = ""
	}

	if a.WithTransactionFeed {
		go func() {
			if err := a.explorer.SubscribeForAddresses([]string{boardingAddr.Address}); err != nil {
				log.WithError(err).Error("failed to subscribe for boarding address")
			}
		}()
	}

	return onchainAddr, offchainAddr.Address, boardingAddr.Address, nil
}

func (a *arkClient) GetAddresses(
	ctx context.Context,
) ([]string, []string, []string, []string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	toStringList := func(l []wallet.TapscriptsAddress) []string {
		res := make([]string, 0, len(l))
		for _, v := range l {
			res = append(res, v.Address)
		}
		return res
	}

	return onchainAddrs, toStringList(offchainAddrs),
		toStringList(boardingAddrs), toStringList(redemptionAddrs), nil
}

func (a *arkClient) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	_, offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}
	return offchainAddr.Address, nil
}

func (a *arkClient) GetTransactionEventChannel(ctx context.Context) <-chan types.TransactionEvent {
	if a.Config != nil && a.WithTransactionFeed {
		if a.txBroadcaster != nil {
			return a.txBroadcaster.Subscribe(0)
		}
	}
	return nil
}

func (a *arkClient) GetVtxoEventChannel(_ context.Context) <-chan types.VtxoEvent {
	if a.Config != nil && a.WithTransactionFeed {
		if a.vtxoBroadcaster != nil {
			return a.vtxoBroadcaster.Subscribe(0)
		}
	}
	return nil
}

func (a *arkClient) GetUtxoEventChannel(_ context.Context) <-chan types.UtxoEvent {
	if a.Config != nil && a.WithTransactionFeed {
		if a.utxoBroadcaster != nil {
			return a.utxoBroadcaster.Subscribe(0)
		}
	}
	return nil
}

func (a *arkClient) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	return a.wallet.SignTransaction(ctx, a.explorer, tx)
}

func (a *arkClient) Reset(ctx context.Context) {
	a.client.Close()
	a.indexer.Close()
	a.explorer.Stop()

	if a.WithTransactionFeed {
		a.syncMu.Lock()
		a.syncDone = false
		a.syncErr = nil
		a.syncMu.Unlock()
	}

	if a.stopFn != nil {
		a.stopFn()
	}
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("wallet reset while restoring"))
		a.syncListeners.clear()
	}
	if a.store != nil {
		a.store.Clean(ctx)
	}
}

func (a *arkClient) Stop() {
	a.client.Close()
	a.indexer.Close()
	a.explorer.Stop()

	if a.WithTransactionFeed {
		a.syncMu.Lock()
		a.syncDone = false
		a.syncErr = nil
		a.syncMu.Unlock()
	}

	if a.stopFn != nil {
		a.stopFn()
	}
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("service stopped while restoring"))
		a.syncListeners.clear()
	}

	a.store.Close()
}

func (a *arkClient) ListSpendableVtxos(ctx context.Context) ([]types.Vtxo, error) {
	if a.WithTransactionFeed {
		if err := a.safeCheck(); err != nil {
			return nil, err
		}
		spendable, err := a.store.VtxoStore().GetSpendableVtxos(ctx)
		if err != nil {
			return nil, err
		}
		return spendable, nil
	}

	spendable, _, err := a.listVtxosFromIndexer(ctx)
	if err != nil {
		return nil, err
	}
	return spendable, nil
}

func (a *arkClient) ListVtxos(ctx context.Context) ([]types.Vtxo, []types.Vtxo, error) {
	if a.WithTransactionFeed {
		if err := a.safeCheck(); err != nil {
			return nil, nil, err
		}
		return a.store.VtxoStore().GetAllVtxos(ctx)
	}

	return a.listVtxosFromIndexer(ctx)
}

func (a *arkClient) NotifyIncomingFunds(ctx context.Context, addr string) ([]types.Vtxo, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	decoded, err := arklib.DecodeAddressV0(addr)
	if err != nil {
		return nil, err
	}
	vtxoScript, err := script.P2TRScript(decoded.VtxoTapKey)
	if err != nil {
		return nil, err
	}

	scripts := []string{hex.EncodeToString(vtxoScript)}
	subId, err := a.indexer.SubscribeForScripts(ctx, "", scripts)
	if err != nil {
		return nil, err
	}

	eventCh, closeFn, err := a.indexer.GetSubscription(ctx, subId)
	if err != nil {
		return nil, err
	}
	defer func() {
		// nolint
		a.indexer.UnsubscribeForScripts(ctx, subId, scripts)
		closeFn()
	}()

	event := <-eventCh

	if event.Err != nil {
		return nil, event.Err
	}
	return event.NewVtxos, nil
}

func (a *arkClient) IsSynced(ctx context.Context) <-chan types.SyncEvent {
	if !a.WithTransactionFeed {
		return nil
	}
	ch := make(chan types.SyncEvent, 1)

	a.syncMu.Lock()
	syncDone := a.syncDone
	syncErr := a.syncErr
	a.syncMu.Unlock()

	if syncDone {
		go func() {
			ch <- types.SyncEvent{
				Synced: syncErr == nil,
				Err:    syncErr,
			}
		}()
		return ch
	}

	a.syncListeners.add(ch)
	return ch
}

func (a *arkClient) initWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.ServerUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}

	explorerOpts := []mempool_explorer.Option{
		mempool_explorer.WithTracker(args.WithTransactionFeed),
	}
	if args.ExplorerPollInterval > 0 {
		explorerOpts = append(
			explorerOpts, mempool_explorer.WithPollInterval(args.ExplorerPollInterval),
		)
	}

	explorerSvc, err := mempool_explorer.NewExplorer(
		args.ExplorerURL, utils.NetworkFromString(info.Network), explorerOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(args.ClientType, args.ServerUrl)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	signerPubkey, err := ecPubkeyFromHex(info.SignerPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse signer pubkey: %s", err)
	}

	forfeitPubkey, err := ecPubkeyFromHex(info.ForfeitPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse forfeit pubkey: %s", err)
	}

	unilateralExitDelayType := arklib.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = arklib.LocktimeTypeSecond
	}

	boardingExitDelayType := arklib.LocktimeTypeBlock
	if info.BoardingExitDelay >= 512 {
		boardingExitDelayType = arklib.LocktimeTypeSecond
	}

	storeData := types.Config{
		ServerUrl:       args.ServerUrl,
		SignerPubKey:    signerPubkey,
		ForfeitPubKey:   forfeitPubkey,
		WalletType:      args.Wallet.GetType(),
		ClientType:      args.ClientType,
		Network:         network,
		SessionDuration: info.SessionDuration,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay),
		},
		Dust: info.Dust,
		BoardingExitDelay: arklib.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(info.BoardingExitDelay),
		},
		ForfeitAddress:               info.ForfeitAddress,
		WithTransactionFeed:          args.WithTransactionFeed,
		ExplorerURL:                  explorerSvc.BaseUrl(),
		ExplorerTrackingPollInterval: args.ExplorerPollInterval,
		UtxoMinAmount:                info.UtxoMinAmount,
		UtxoMaxAmount:                info.UtxoMaxAmount,
		VtxoMinAmount:                info.VtxoMinAmount,
		VtxoMaxAmount:                info.VtxoMaxAmount,
		CheckpointTapscript:          info.CheckpointTapscript,
		Fees:                         info.Fees,
	}
	if err := a.store.ConfigStore().AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := args.Wallet.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.ConfigStore().CleanData(ctx)
		return err
	}

	a.Config = &storeData
	a.wallet = args.Wallet
	a.explorer = explorerSvc
	a.client = clientSvc
	a.indexer = indexerSvc

	return nil
}

func (a *arkClient) init(ctx context.Context, args InitArgs) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.ServerUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}
	explorerOpts := []mempool_explorer.Option{
		mempool_explorer.WithTracker(args.WithTransactionFeed),
	}
	if args.ExplorerPollInterval > 0 {
		explorerOpts = append(
			explorerOpts, mempool_explorer.WithPollInterval(args.ExplorerPollInterval),
		)
	}

	explorerSvc, err := mempool_explorer.NewExplorer(
		args.ExplorerURL, utils.NetworkFromString(info.Network), explorerOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(args.ClientType, args.ServerUrl)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	signerPubkey, err := ecPubkeyFromHex(info.SignerPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse signer pubkey: %s", err)
	}

	forfeitPubkey, err := ecPubkeyFromHex(info.ForfeitPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse forfeit pubkey: %s", err)
	}

	unilateralExitDelayType := arklib.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = arklib.LocktimeTypeSecond
	}

	boardingExitDelayType := arklib.LocktimeTypeBlock
	if info.BoardingExitDelay >= 512 {
		boardingExitDelayType = arklib.LocktimeTypeSecond
	}

	cfgData := types.Config{
		ServerUrl:       args.ServerUrl,
		SignerPubKey:    signerPubkey,
		ForfeitPubKey:   forfeitPubkey,
		WalletType:      args.WalletType,
		ClientType:      args.ClientType,
		Network:         network,
		SessionDuration: info.SessionDuration,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay),
		},
		Dust: info.Dust,
		BoardingExitDelay: arklib.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(info.BoardingExitDelay),
		},
		ExplorerURL:                  explorerSvc.BaseUrl(),
		ExplorerTrackingPollInterval: args.ExplorerPollInterval,
		ForfeitAddress:               info.ForfeitAddress,
		WithTransactionFeed:          args.WithTransactionFeed,
		UtxoMinAmount:                info.UtxoMinAmount,
		UtxoMaxAmount:                info.UtxoMaxAmount,
		VtxoMinAmount:                info.VtxoMinAmount,
		VtxoMaxAmount:                info.VtxoMaxAmount,
		CheckpointTapscript:          info.CheckpointTapscript,
		Fees:                         info.Fees,
	}
	walletSvc, err := getWallet(a.store.ConfigStore(), &cfgData, supportedWallets)
	if err != nil {
		return err
	}

	if err := a.store.ConfigStore().AddData(ctx, cfgData); err != nil {
		return err
	}

	if _, err := walletSvc.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.ConfigStore().CleanData(ctx)
		return err
	}

	a.Config = &cfgData
	a.wallet = walletSvc
	a.explorer = explorerSvc
	a.client = clientSvc
	a.indexer = indexerSvc

	return nil
}

func (a *arkClient) listVtxosFromIndexer(
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

func (a *arkClient) listPendingSpentVtxosFromIndexer(ctx context.Context) ([]types.Vtxo, error) {
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

func (a *arkClient) safeCheck() error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}
	if a.WithTransactionFeed {
		a.syncMu.Lock()
		syncDone := a.syncDone
		syncErr := a.syncErr
		a.syncMu.Unlock()
		if !syncDone {
			if syncErr != nil {
				return fmt.Errorf("failed to restore wallet: %s", syncErr)
			}
			return fmt.Errorf("wallet is still syncing")
		}
	}
	return nil
}

func (a *arkClient) setRestored(err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	a.syncDone = true
	a.syncErr = err

	a.syncListeners.broadcast(err)
	a.syncListeners.clear()

}

func (a *arkClient) listenDbEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			time.Sleep(100 * time.Millisecond)
			if a.utxoBroadcaster != nil {
				a.utxoBroadcaster.Close()
			}
			if a.vtxoBroadcaster != nil {
				a.vtxoBroadcaster.Close()
			}
			if a.txBroadcaster != nil {
				a.txBroadcaster.Close()
			}
			return
		case event, ok := <-a.store.UtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.utxoBroadcaster.Publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send utxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-a.store.VtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.vtxoBroadcaster.Publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send vtxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-a.store.TransactionStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.txBroadcaster.Publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send utxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		}
	}
}

func (a *arkClient) periodicRefreshDb(ctx context.Context) {
	if a.refreshDbInterval == 0 {
		return
	}
	ticker := time.NewTicker(a.refreshDbInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.refreshDb(ctx); err != nil {
				log.WithError(err).Error("failed to refresh db")
			}
		}
	}
}

func (a *arkClient) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	vtxos, err := a.listPendingSpentVtxosFromIndexer(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if createdAfter != nil && !createdAfter.IsZero() {
			if !vtxo.CreatedAt.After(*createdAfter) {
				continue
			}
		}
		filtered = append(filtered, vtxo)
	}

	if len(filtered) == 0 {
		return nil, nil
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, filtered)
	if err != nil {
		return nil, err
	}

	inputs, exitLeaves, arkFields, err := toIntentInputs(nil, vtxosWithTapscripts, nil)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0)
	const MAX_INPUTS_PER_INTENT = 20

	for i := 0; i < len(inputs); i += MAX_INPUTS_PER_INTENT {
		end := min(i+MAX_INPUTS_PER_INTENT, len(inputs))
		inputsSubset := inputs[i:end]
		exitLeavesSubset := exitLeaves[i:end]
		arkFieldsSubset := arkFields[i:end]
		proofTx, message, err := a.makeGetPendingTxIntent(
			inputsSubset, exitLeavesSubset, arkFieldsSubset,
		)
		if err != nil {
			return nil, err
		}

		pendingTxs, err := a.client.GetPendingTx(ctx, proofTx, message)
		if err != nil {
			return nil, err
		}

		for _, tx := range pendingTxs {
			txid, err := a.finalizeTx(ctx, tx)
			if err != nil {
				log.WithError(err).Errorf("failed to finalize pending tx: %s", tx.Txid)
				continue
			}
			txids = append(txids, txid)
		}
	}

	return txids, nil
}

func (a *arkClient) finalizeTx(
	ctx context.Context, acceptedTx client.AcceptedOffchainTx,
) (string, error) {
	finalCheckpoints := make([]string, 0, len(acceptedTx.SignedCheckpointTxs))

	for _, checkpoint := range acceptedTx.SignedCheckpointTxs {
		signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, checkpoint)
		if err != nil {
			return "", err
		}
		finalCheckpoints = append(finalCheckpoints, signedTx)
	}

	if err := a.client.FinalizeTx(ctx, acceptedTx.Txid, finalCheckpoints); err != nil {
		return "", err
	}

	return acceptedTx.Txid, nil
}

func getClient(
	supportedClients utils.SupportedType[utils.ClientFactory], clientType, serverUrl string,
) (client.TransportClient, error) {
	factory := supportedClients[clientType]
	return factory(serverUrl)
}

func getIndexer(clientType, serverUrl string) (indexer.Indexer, error) {
	if clientType != GrpcClient && clientType != RestClient {
		return nil, fmt.Errorf("invalid client type")
	}
	if clientType == GrpcClient {
		return grpcindexer.NewClient(serverUrl)
	}
	return restindexer.NewClient(serverUrl)
}

func getWallet(
	configStore types.ConfigStore, data *types.Config,
	supportedWallets utils.SupportedType[struct{}],
) (wallet.WalletService, error) {
	switch data.WalletType {
	case wallet.SingleKeyWallet:
		return getSingleKeyWallet(configStore)
	default:
		return nil, fmt.Errorf(
			"unsupported wallet type '%s', please select one of: %s",
			data.WalletType, supportedWallets,
		)
	}
}

func getSingleKeyWallet(configStore types.ConfigStore) (wallet.WalletService, error) {
	walletStore, err := getWalletStore(configStore.GetType(), configStore.GetDatadir())
	if err != nil {
		return nil, err
	}

	return singlekeywallet.NewBitcoinWallet(configStore, walletStore)
}

func getWalletStore(storeType, datadir string) (walletstore.WalletStore, error) {
	switch storeType {
	case types.InMemoryStore:
		return inmemorystore.NewWalletStore()
	case types.FileStore:
		return filestore.NewWalletStore(datadir)
	default:
		return nil, fmt.Errorf("unknown wallet store type")
	}
}

func filterByOutpoints(vtxos []types.Vtxo, outpoints []types.Outpoint) []types.Vtxo {
	filtered := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		for _, outpoint := range outpoints {
			if vtxo.Outpoint == outpoint {
				filtered = append(filtered, vtxo)
			}
		}
	}
	return filtered
}

type syncListeners struct {
	lock      *sync.RWMutex
	listeners map[chan types.SyncEvent]struct{}
}

func newReadyListeners() *syncListeners {
	return &syncListeners{
		lock:      &sync.RWMutex{},
		listeners: make(map[chan types.SyncEvent]struct{}),
	}
}

func (l *syncListeners) add(ch chan types.SyncEvent) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.listeners[ch] = struct{}{}
}

func (l *syncListeners) broadcast(err error) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	for ch := range l.listeners {
		ch <- types.SyncEvent{Synced: err == nil, Err: err}
	}
}

func (l *syncListeners) clear() {
	l.lock.Lock()
	defer l.lock.Unlock()
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = make(map[chan types.SyncEvent]struct{})
}

package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	grpcindexer "github.com/ark-network/ark/pkg/client-sdk/indexer/grpc"
	restindexer "github.com/ark-network/ark/pkg/client-sdk/indexer/rest"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	BitcoinExplorer = explorer.BitcoinExplorer
)

var (
	ErrAlreadyInitialized = fmt.Errorf("client already initialized")
	ErrNotInitialized     = fmt.Errorf("client not initialized")
)

var (
	defaultNetworks = utils.SupportedType[string]{
		common.Bitcoin.Name:        "https://mempool.space/api",
		common.BitcoinTestNet.Name: "https://mempool.space/testnet/api",
		//common.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
		common.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
		common.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
		common.BitcoinRegTest.Name:   "http://localhost:3000",
	}
)

type arkClient struct {
	*types.Config
	wallet   wallet.WalletService
	store    types.Store
	explorer explorer.Explorer
	client   client.TransportClient
	indexer  indexer.Indexer

	txStreamCtxCancel context.CancelFunc
}

func (a *arkClient) GetVersion() string {
	return Version
}

func (a *arkClient) GetConfigData(
	_ context.Context,
) (*types.Config, error) {
	if a.Config == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.Config, nil
}

func (a *arkClient) Unlock(ctx context.Context, pasword string) error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	_, err := a.wallet.Unlock(ctx, pasword)
	return err
}

func (a *arkClient) Lock(ctx context.Context) error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	return a.wallet.Lock(ctx)
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

	return onchainAddr, offchainAddr.Address, boardingAddr.Address, nil
}

func (a *arkClient) GetTransactionEventChannel(_ context.Context) chan types.TransactionEvent {
	if a.store != nil && a.store.TransactionStore() != nil {
		return a.store.TransactionStore().GetEventChannel()
	}
	return nil
}

func (a *arkClient) GetVtxoEventChannel(_ context.Context) chan types.VtxoEvent {
	if a.store != nil && a.store.VtxoStore() != nil {
		return a.store.VtxoStore().GetEventChannel()
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
	if a.txStreamCtxCancel != nil {
		a.txStreamCtxCancel()
	}
	if a.store != nil {
		a.store.Clean(ctx)
	}
}

func (a *arkClient) Stop() {
	if a.txStreamCtxCancel != nil {
		a.txStreamCtxCancel()
	}

	a.store.Close()
}

func (a *arkClient) ListVtxos(ctx context.Context) (
	spendableVtxos, spentVtxos []types.Vtxo, err error,
) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return
	}

	scripts := make([]string, 0, len(offchainAddrs))
	for _, addr := range offchainAddrs {
		decoded, err := common.DecodeAddressV0(addr.Address)
		if err != nil {
			return nil, nil, err
		}
		script, err := common.P2TRScript(decoded.VtxoTapKey)
		if err != nil {
			return nil, nil, err
		}
		scripts = append(scripts, hex.EncodeToString(script))
	}
	opt := indexer.GetVtxosRequestOption{}
	if err = opt.WithScripts(scripts); err != nil {
		return
	}

	resp, err := a.indexer.GetVtxos(ctx, opt)
	if err != nil {
		return
	}

	for _, vtxo := range resp.Vtxos {
		if vtxo.Spent || vtxo.Swept || vtxo.Unrolled {
			spentVtxos = append(spentVtxos, vtxo)
			continue
		}
		spendableVtxos = append(spendableVtxos, vtxo)
	}

	return
}

func (a *arkClient) NotifyIncomingFunds(
	ctx context.Context, addr string,
) ([]types.Vtxo, error) {
	if a.client == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	decoded, err := common.DecodeAddressV0(addr)
	if err != nil {
		return nil, err
	}
	script, err := common.P2TRScript(decoded.VtxoTapKey)
	if err != nil {
		return nil, err
	}

	scripts := []string{hex.EncodeToString(script)}
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

func (a *arkClient) initWithWallet(
	ctx context.Context, args InitWithWalletArgs,
) error {
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

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(args.ClientType, args.ServerUrl)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse signer pubkey: %s", err)
	}
	signerPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if info.VtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	boardingExitDelayType := common.LocktimeTypeBlock
	if info.BoardingExitDelay >= 512 {
		boardingExitDelayType = common.LocktimeTypeSecond
	}

	storeData := types.Config{
		ServerUrl:    args.ServerUrl,
		SignerPubKey: signerPubkey,
		WalletType:   args.Wallet.GetType(),
		ClientType:   args.ClientType,
		Network:      network,
		VtxoTreeExpiry: common.RelativeLocktime{
			Type: vtxoTreeExpiryType, Value: uint32(info.VtxoTreeExpiry),
		},
		RoundInterval: info.RoundInterval,
		UnilateralExitDelay: common.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay),
		},
		Dust: info.Dust,
		BoardingExitDelay: common.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(info.BoardingExitDelay),
		},
		ForfeitAddress:          info.ForfeitAddress,
		WithTransactionFeed:     args.WithTransactionFeed,
		MarketHourStartTime:     info.MarketHourStartTime,
		MarketHourEndTime:       info.MarketHourEndTime,
		MarketHourPeriod:        info.MarketHourPeriod,
		MarketHourRoundInterval: info.MarketHourRoundInterval,
		ExplorerURL:             explorerSvc.BaseUrl(),
		UtxoMinAmount:           info.UtxoMinAmount,
		UtxoMaxAmount:           info.UtxoMaxAmount,
		VtxoMinAmount:           info.VtxoMinAmount,
		VtxoMaxAmount:           info.VtxoMaxAmount,
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

func (a *arkClient) init(
	ctx context.Context, args InitArgs,
) error {
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

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(args.ClientType, args.ServerUrl)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse signer pubkey: %s", err)
	}
	signerPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if info.VtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	boardingExitDelayType := common.LocktimeTypeBlock
	if info.BoardingExitDelay >= 512 {
		boardingExitDelayType = common.LocktimeTypeSecond
	}

	cfgData := types.Config{
		ServerUrl:    args.ServerUrl,
		SignerPubKey: signerPubkey,
		WalletType:   args.WalletType,
		ClientType:   args.ClientType,
		Network:      network,
		VtxoTreeExpiry: common.RelativeLocktime{
			Type: vtxoTreeExpiryType, Value: uint32(info.VtxoTreeExpiry),
		},
		RoundInterval: info.RoundInterval,
		UnilateralExitDelay: common.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay),
		},
		Dust: info.Dust,
		BoardingExitDelay: common.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(info.BoardingExitDelay),
		},
		ExplorerURL:             explorerSvc.BaseUrl(),
		ForfeitAddress:          info.ForfeitAddress,
		WithTransactionFeed:     args.WithTransactionFeed,
		MarketHourStartTime:     info.MarketHourStartTime,
		MarketHourEndTime:       info.MarketHourEndTime,
		MarketHourPeriod:        info.MarketHourPeriod,
		MarketHourRoundInterval: info.MarketHourRoundInterval,
		UtxoMinAmount:           info.UtxoMinAmount,
		UtxoMaxAmount:           info.UtxoMaxAmount,
		VtxoMinAmount:           info.VtxoMinAmount,
		VtxoMaxAmount:           info.VtxoMaxAmount,
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

func (a *arkClient) safeCheck() error {
	if a.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}
	return nil
}

func getClient(
	supportedClients utils.SupportedType[utils.ClientFactory], clientType, serverUrl string,
) (client.TransportClient, error) {
	factory := supportedClients[clientType]
	return factory(serverUrl)
}

func getExplorer(explorerURL, network string) (explorer.Explorer, error) {
	if explorerURL == "" {
		var ok bool
		if explorerURL, ok = defaultNetworks[network]; !ok {
			return nil, fmt.Errorf("invalid network")
		}
	}
	return explorer.NewExplorer(explorerURL, utils.NetworkFromString(network)), nil
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

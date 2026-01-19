package arksdk

import (
	"context"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	restclient "github.com/arkade-os/arkd/pkg/client-lib/client/rest"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	restindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/rest"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

var (
	supportedClients = utils.SupportedType[utils.ClientFactory]{
		GrpcClient: grpcclient.NewClient,
		RestClient: restclient.NewClient,
	}
	supportedIndexers = utils.SupportedType[utils.IndexerFactory]{
		GrpcClient: grpcindexer.NewClient,
		RestClient: restindexer.NewClient,
	}
)

func (a *service) Init(ctx context.Context, args InitArgs) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}
	walletSvc, err := getWallet(a.store.ConfigStore(), args.WalletType, supportedWallets)
	if err != nil {
		return err
	}
	if _, err := walletSvc.Create(ctx, args.Password, args.Seed); err != nil {
		return err
	}

	return a.init(ctx, args.parse(), walletSvc)
}

func (a *service) InitWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	if _, err := args.Wallet.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.ConfigStore().CleanData(ctx)
		return err
	}

	return a.init(ctx, args.parse(), args.Wallet)
}

func (a *service) init(ctx context.Context, args args, walletSvc wallet.WalletService) error {
	clientSvc, err := getClient(
		supportedClients, args.clientType, args.serverUrl, a.withMonitorConn,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}

	indexerSvc, err := getIndexer(
		supportedIndexers, args.clientType, args.serverUrl, a.withMonitorConn,
	)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	explorerSvc := a.explorer
	if explorerSvc == nil {
		explorerOpts := []mempool_explorer.Option{
			mempool_explorer.WithTracker(false),
		}
		explorerSvc, err = mempool_explorer.NewExplorer(
			args.explorerURL, utils.NetworkFromString(info.Network), explorerOpts...,
		)
		if err != nil {
			return fmt.Errorf("failed to setup explorer: %s", err)
		}
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
		ServerUrl:       args.serverUrl,
		SignerPubKey:    signerPubkey,
		ForfeitPubKey:   forfeitPubkey,
		WalletType:      args.walletType,
		ClientType:      args.clientType,
		Network:         network,
		SessionDuration: info.SessionDuration,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay),
		},
		Dust: info.Dust,
		BoardingExitDelay: arklib.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(info.BoardingExitDelay),
		},
		ExplorerURL:         explorerSvc.BaseUrl(),
		ForfeitAddress:      info.ForfeitAddress,
		UtxoMinAmount:       info.UtxoMinAmount,
		UtxoMaxAmount:       info.UtxoMaxAmount,
		VtxoMinAmount:       info.VtxoMinAmount,
		VtxoMaxAmount:       info.VtxoMaxAmount,
		CheckpointTapscript: info.CheckpointTapscript,
		Fees:                info.Fees,
	}
	if err := a.store.ConfigStore().AddData(ctx, cfgData); err != nil {
		return err
	}

	a.Config = &cfgData
	a.wallet = walletSvc
	a.client = clientSvc
	a.indexer = indexerSvc
	if a.explorer == nil {
		a.explorer = explorerSvc
	}

	return nil
}

type InitArgs struct {
	ClientType  string
	WalletType  string
	ServerUrl   string
	Seed        string
	Password    string
	ExplorerURL string
}

func (a InitArgs) validate() error {
	if len(a.WalletType) <= 0 {
		return fmt.Errorf("missing wallet")
	}
	if !supportedWallets.Supports(a.WalletType) {
		return fmt.Errorf(
			"wallet type '%s' not supported, please select one of: %s",
			a.WalletType, supportedWallets,
		)
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.Supports(a.ClientType) {
		return fmt.Errorf(
			"client type '%s' not supported, please select one of: %s",
			a.ClientType, supportedClients,
		)
	}

	if len(a.ServerUrl) <= 0 {
		return fmt.Errorf("missing server url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}

	return nil
}

func (a InitArgs) parse() args {
	return args{a.ClientType, a.WalletType, a.ServerUrl, a.Seed, a.Password, a.ExplorerURL}
}

type InitWithWalletArgs struct {
	ClientType  string
	Wallet      wallet.WalletService
	ServerUrl   string
	Seed        string
	Password    string
	ExplorerURL string
}

func (a InitWithWalletArgs) validate() error {
	if a.Wallet == nil {
		return fmt.Errorf("missing wallet")
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.Supports(a.ClientType) {
		return fmt.Errorf("client type not supported, please select one of: %s", supportedClients)
	}

	if len(a.ServerUrl) <= 0 {
		return fmt.Errorf("missing server url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}
	return nil
}

func (a InitWithWalletArgs) parse() args {
	return args{a.ClientType, a.Wallet.GetType(), a.ServerUrl, a.Seed, a.Password, a.ExplorerURL}
}

type args struct {
	clientType  string
	walletType  string
	serverUrl   string
	seed        string
	password    string
	explorerURL string
}

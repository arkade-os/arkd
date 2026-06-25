package wallet

import (
	"context"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
)

func (w *wallet) Init(ctx context.Context, args InitArgs) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}
	if w.identity == nil {
		return ErrNotInitialized
	}

	return w.init(ctx, args.parse(), args.Explorer)
}

func (w *wallet) init(
	ctx context.Context, args args, explorerSvc clientlib.Explorer,
) error {
	clientSvc, err := client.NewClient(args.serverUrl, w.clientVersion)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}

	indexerSvc, err := indexer.NewClient(args.serverUrl)
	if err != nil {
		return fmt.Errorf("failed to setup indexer: %s", err)
	}

	if explorerSvc == nil {
		explorerOpts := []explorer.Option{
			explorer.WithTracker(false),
		}
		explorerSvc, err = explorer.NewExplorer(
			args.explorerURL, clientlib.NetworkFromString(info.Network), explorerOpts...,
		)
		if err != nil {
			return fmt.Errorf("failed to setup explorer: %s", err)
		}
	}

	network := clientlib.NetworkFromString(info.Network)

	if _, err := w.identity.Create(
		ctx, clientlib.ToBitcoinNetwork(network), args.password, args.seed,
	); err != nil {
		return err
	}

	signerPubkey, err := ecPubkeyFromHex(info.SignerPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse signer pubkey: %s", err)
	}

	forfeitPubkey, err := ecPubkeyFromHex(info.ForfeitPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse forfeit pubkey: %s", err)
	}

	// TODO: Drop me once go-sdk handles arkd config changes properly
	unilateralExitDelay := uint32(info.UnilateralExitDelay)
	if network.Name == arklib.Bitcoin.Name {
		unilateralExitDelay = 605184
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
		Network:         network,
		SessionDuration: info.SessionDuration,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type: unilateralExitDelayType, Value: unilateralExitDelay,
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
		Fees:                types.FeeInfo(info.Fees),
	}
	if err := w.store.AddData(ctx, cfgData); err != nil {
		return err
	}

	w.Config = &cfgData
	w.client = clientSvc
	w.indexer = indexerSvc
	if w.explorer == nil {
		w.explorer = explorerSvc
	}

	return nil
}

type InitArgs struct {
	ServerUrl   string
	Seed        string
	Password    string
	ExplorerURL string
	Explorer    clientlib.Explorer
}

func (a InitArgs) validate() error {
	if a.Explorer == nil && len(a.ExplorerURL) <= 0 {
		return fmt.Errorf("missing explorer or explorer url")
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
	explorerUrl := a.ExplorerURL
	if a.Explorer != nil {
		explorerUrl = a.Explorer.BaseUrl()
	}
	return args{a.ServerUrl, a.Seed, a.Password, explorerUrl}
}

type args struct {
	serverUrl   string
	seed        string
	password    string
	explorerURL string
}

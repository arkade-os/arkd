package wallet

import (
	"context"
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
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

	cfgData, err := info.ServerParams(args.serverUrl, explorerSvc.BaseUrl())
	if err != nil {
		return fmt.Errorf("failed to parse server params: %w", err)
	}

	if _, err := w.identity.Create(
		ctx, clientlib.ToBitcoinNetwork(cfgData.Network), args.password, args.seed,
	); err != nil {
		return err
	}

	if err := w.store.AddData(ctx, *cfgData); err != nil {
		return err
	}

	w.ServerParams = cfgData
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

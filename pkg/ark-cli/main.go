package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

const (
	DatadirEnvVar = "ARK_WALLET_DATADIR"
)

var (
	Version      string
	arkSdkClient arksdk.ArkClient
)

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "Ark CLI"
	app.Usage = "ark wallet command line interface"
	app.Commands = append(
		app.Commands,
		&initCommand,
		&configCommand,
		&dumpCommand,
		&receiveCommand,
		&settleCmd,
		&sendCommand,
		&balanceCommand,
		&redeemCommand,
		&notesCommand,
		&recoverCommand,
		&versionCommand,
		&issueCommand,
		&reissueCommand,
		&burnCommand,
		&vtxosCommand,
	)
	app.Flags = []cli.Flag{datadirFlag, verboseFlag}
	app.Before = func(ctx *cli.Context) error {
		sdk, err := getArkSdkClient(ctx)
		if err != nil {
			return fmt.Errorf("error initializing ark sdk client: %v", err)
		}
		arkSdkClient = sdk

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(fmt.Errorf("error: %v", err))
		os.Exit(1)
	}
}

var (
	datadirFlag = &cli.StringFlag{
		Name:     "datadir",
		Usage:    "Specify the data directory",
		Required: false,
		Value:    arklib.AppDataDir("ark-cli", false),
		EnvVars:  []string{DatadirEnvVar},
	}
	explorerFlag = &cli.StringFlag{
		Name:  "explorer",
		Usage: "the url of the explorer to use",
	}
	passwordFlag = &cli.StringFlag{
		Name:  "password",
		Usage: "password to unlock the wallet",
	}
	expiryDetailsFlag = &cli.BoolFlag{
		Name:  "compute-expiry-details",
		Usage: "compute client-side VTXOs expiry time",
	}
	privateKeyFlag = &cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional private key to encrypt",
	}
	urlFlag = &cli.StringFlag{
		Name:     "server-url",
		Usage:    "the url of the Ark server to connect to",
		Required: true,
	}
	receiversFlag = &cli.StringFlag{
		Name:  "receivers",
		Usage: "JSON encoded receivers of the send transaction",
	}
	toFlag = &cli.StringFlag{
		Name:  "to",
		Usage: "recipient address",
	}
	amountFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to send in sats",
	}
	controlAssetAmountFlag = &cli.Uint64Flag{
		Name:  "control-amount",
		Usage: "amount of the control asset in sats",
		Value: 0,
	}
	controlAssetIDFlag = &cli.StringFlag{
		Name:  "control-asset-id",
		Usage: "asset id of the control asset to spend for reissue",
	}
	enableExpiryCoinselectFlag = &cli.BoolFlag{
		Name:  "enable-expiry-coinselect",
		Usage: "select VTXOs about to expire first",
	}
	addressFlag = &cli.StringFlag{
		Name:  "address",
		Usage: "main chain address receiving the redeemed VTXO",
	}
	amountToRedeemFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to redeem",
	}
	forceFlag = &cli.BoolFlag{
		Name:  "force",
		Usage: "force redemption without collaboration",
	}
	notesFlag = &cli.StringSliceFlag{
		Name:    "notes",
		Aliases: []string{"n"},
		Usage:   "notes to redeem",
	}
	restFlag = &cli.BoolFlag{
		Name:        "rest",
		Usage:       "use REST client instead of gRPC",
		Value:       false,
		DefaultText: "false",
	}
	completeFlag = &cli.BoolFlag{
		Name:        "complete",
		Usage:       "complete the unilateral exit after timelock expired",
		Value:       false,
		DefaultText: "false",
	}
	verboseFlag = &cli.BoolFlag{
		Name:        "verbose",
		Usage:       "enable debug logs",
		Value:       false,
		DefaultText: "false",
	}
	metadataFlag = &cli.StringSliceFlag{
		Name:    "metadata",
		Aliases: []string{"m"},
		Usage:   "metadata to add to the asset",
	}
	assetIDFlag = &cli.StringFlag{
		Name:  "asset-id",
		Usage: "asset id to send",
	}
	spentFlag = &cli.BoolFlag{
		Name:  "spent",
		Usage: "show spent vtxos instead of spendable",
	}
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize Ark wallet with encryption password, connect to Ark server",
		Action: func(ctx *cli.Context) error {
			return initArkSdk(ctx)
		},
		Flags: []cli.Flag{passwordFlag, privateKeyFlag, urlFlag, explorerFlag, restFlag},
	}
	configCommand = cli.Command{
		Name:  "config",
		Usage: "Shows Ark wallet configuration",
		Action: func(ctx *cli.Context) error {
			return config(ctx)
		},
	}
	dumpCommand = cli.Command{
		Name:  "dump-privkey",
		Usage: "Dumps private key of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			return dumpPrivKey(ctx)
		},
		Flags: []cli.Flag{passwordFlag},
	}
	receiveCommand = cli.Command{
		Name:  "receive",
		Usage: "Shows boarding and offchain addresses",
		Action: func(ctx *cli.Context) error {
			return receive(ctx)
		},
	}
	settleCmd = cli.Command{
		Name:  "settle",
		Usage: "Settle onboarding or pending funds",
		Action: func(ctx *cli.Context) error {
			return settle(ctx)
		},
		Flags: []cli.Flag{passwordFlag},
	}
	balanceCommand = cli.Command{
		Name:  "balance",
		Usage: "Shows onchain and offchain Ark wallet balance",
		Action: func(ctx *cli.Context) error {
			return balance(ctx)
		},
		Flags: []cli.Flag{expiryDetailsFlag},
	}
	sendCommand = cli.Command{
		Name:  "send",
		Usage: "Send funds offchain",
		Action: func(ctx *cli.Context) error {
			return send(ctx)
		},
		Flags: []cli.Flag{
			receiversFlag,
			toFlag,
			amountFlag,
			enableExpiryCoinselectFlag,
			assetIDFlag,
			passwordFlag,
		},
	}
	redeemCommand = cli.Command{
		Name:  "redeem",
		Usage: "Redeem offchain funds, collaboratively or unilaterally",
		Flags: []cli.Flag{addressFlag, amountToRedeemFlag, forceFlag, passwordFlag, completeFlag},
		Action: func(ctx *cli.Context) error {
			return redeem(ctx)
		},
	}
	notesCommand = cli.Command{
		Name:  "redeem-notes",
		Usage: "Redeem offchain notes",
		Flags: []cli.Flag{notesFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return redeemNotes(ctx)
		},
	}
	recoverCommand = cli.Command{
		Name:  "recover",
		Usage: "Recover unspent and swept vtxos",
		Flags: []cli.Flag{passwordFlag},
		Action: func(ctx *cli.Context) error {
			return recoverVtxos(ctx)
		},
	}
	issueCommand = cli.Command{
		Name:  "issue",
		Usage: "Issue a new asset",
		Flags: []cli.Flag{amountFlag, metadataFlag, passwordFlag, controlAssetAmountFlag},
		Action: func(ctx *cli.Context) error {
			return issue(ctx)
		},
	}
	reissueCommand = cli.Command{
		Name:  "reissue",
		Usage: "Reissue more of an existing asset",
		Flags: []cli.Flag{controlAssetIDFlag, assetIDFlag, amountFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return reissue(ctx)
		},
	}
	burnCommand = cli.Command{
		Name:  "burn",
		Usage: "Burn an asset",
		Flags: []cli.Flag{amountFlag, assetIDFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return burn(ctx)
		},
	}
	vtxosCommand = cli.Command{
		Name:  "vtxos",
		Usage: "List vtxos (spendable by default, or spent with --spent flag)",
		Flags: []cli.Flag{spentFlag},
		Action: func(ctx *cli.Context) error {
			return listVtxos(ctx)
		},
	}
	versionCommand = cli.Command{
		Name:  "version",
		Usage: "Display version information",
		Action: func(ctx *cli.Context) error {
			fmt.Printf("Ark CLI version: %s\n", Version)
			return nil
		},
	}
)

func initArkSdk(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	clientType := arksdk.GrpcClient
	if ctx.Bool(restFlag.Name) {
		clientType = arksdk.RestClient
	}

	return arkSdkClient.Init(
		ctx.Context, arksdk.InitArgs{
			ClientType:  clientType,
			WalletType:  arksdk.SingleKeyWallet,
			ServerUrl:   ctx.String(urlFlag.Name),
			Seed:        ctx.String(privateKeyFlag.Name),
			Password:    string(password),
			ExplorerURL: ctx.String(explorerFlag.Name),
		},
	)
}

func config(ctx *cli.Context) error {
	cfgData, err := arkSdkClient.GetConfigData(ctx.Context)
	if err != nil {
		return err
	}

	cfg := map[string]any{
		"server_url":            cfgData.ServerUrl,
		"signer_pubkey":         hex.EncodeToString(cfgData.SignerPubKey.SerializeCompressed()),
		"wallet_type":           cfgData.WalletType,
		"client_type":           cfgData.ClientType,
		"network":               cfgData.Network.Name,
		"unilateral_exit_delay": cfgData.UnilateralExitDelay,
		"dust":                  cfgData.Dust,
		"boarding_exit_delay":   cfgData.BoardingExitDelay,
		"explorer_url":          cfgData.ExplorerURL,
		"forfeit_address":       cfgData.ForfeitAddress,
		"utxo_min_amount":       cfgData.UtxoMinAmount,
		"utxo_max_amount":       cfgData.UtxoMaxAmount,
		"vtxo_min_amount":       cfgData.VtxoMinAmount,
		"vtxo_max_amount":       cfgData.VtxoMaxAmount,
	}

	return printJSON(cfg)
}

func dumpPrivKey(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	privateKey, err := arkSdkClient.Dump(ctx.Context)
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"private_key": privateKey,
	})
}

func receive(ctx *cli.Context) error {
	onchainAddr, offchainAddr, boardingAddr, err := arkSdkClient.Receive(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"boarding_address": boardingAddr,
		"offchain_address": offchainAddr,
		"onchain_address":  onchainAddr,
	})
}

func settle(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	txID, err := arkSdkClient.Settle(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func send(ctx *cli.Context) error {
	receiversJSON := ctx.String(receiversFlag.Name)
	to := ctx.String(toFlag.Name)
	amount := ctx.Uint64(amountFlag.Name)
	assetID := ctx.String(assetIDFlag.Name)
	if receiversJSON == "" && to == "" && amount == 0 && assetID == "" {
		return fmt.Errorf("missing destination, use --to and --amount or --receivers")
	}

	var receivers []types.Receiver
	var err error
	if receiversJSON != "" {
		// set of receivers from JSON
		receivers, err = parseReceivers(receiversJSON)
		if err != nil {
			return err
		}
	} else {
		// if assetID is provided we send dust+1 with the asset
		if len(assetID) > 0 {
			cfg, err := arkSdkClient.GetConfigData(ctx.Context)
			if err != nil {
				return err
			}
			receivers = []types.Receiver{{
				To: to, Amount: cfg.Dust + 1,
				Assets: []types.Asset{{AssetId: assetID, Amount: amount}},
			}}
		} else {
			// otherwise, we treat the amount as a bitcoin amount
			receivers = []types.Receiver{{To: to, Amount: amount}}
		}
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	return sendBitcoin(ctx, receivers)
}

func balance(ctx *cli.Context) error {
	bal, err := arkSdkClient.Balance(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(bal)
}

func redeem(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	force := ctx.Bool(forceFlag.Name)
	complete := ctx.Bool(completeFlag.Name)
	address := ctx.String(addressFlag.Name)
	amount := ctx.Uint64(amountToRedeemFlag.Name)

	if force && complete {
		return fmt.Errorf("cannot use --force and --complete at the same time")
	}

	if force {
		return arkSdkClient.Unroll(ctx.Context)
	}

	if complete {
		txID, err := arkSdkClient.CompleteUnroll(ctx.Context, address)
		if err != nil {
			return err
		}
		return printJSON(map[string]interface{}{
			"txid": txID,
		})
	}

	if amount == 0 {
		return fmt.Errorf("missing amount")
	}
	txID, err := arkSdkClient.CollaborativeExit(
		ctx.Context, address, amount,
	)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func recoverVtxos(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	txid, err := arkSdkClient.Settle(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txid,
	})
}

func redeemNotes(ctx *cli.Context) error {
	notes := ctx.StringSlice(notesFlag.Name)

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	txID, err := arkSdkClient.RedeemNotes(ctx.Context, notes)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func issue(ctx *cli.Context) error {
	amount := ctx.Uint64(amountFlag.Name)
	controlAssetAmount := ctx.Uint64(controlAssetAmountFlag.Name)
	metadata := ctx.StringSlice(metadataFlag.Name)

	if amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	metadataList := make([]asset.Metadata, 0)
	for _, meta := range metadata {
		k, v, ok := strings.Cut(meta, "=") // Go 1.20+
		if !ok {
			return fmt.Errorf("invalid meta %q, expected key=value", meta)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return fmt.Errorf("empty key in %q", meta)
		}
		metadataList = append(metadataList, asset.Metadata{
			Key:   []byte(k),
			Value: []byte(v),
		})
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	var controlAssetPolicy types.ControlAsset = nil
	if controlAssetAmount > 0 {
		controlAssetPolicy = types.NewControlAsset{Amount: controlAssetAmount}
	}

	arkTxid, assetIds, err := arkSdkClient.IssueAsset(
		ctx.Context, amount, controlAssetPolicy, metadataList,
	)
	if err != nil {
		return err
	}

	assetIdsString := make([]string, 0, len(assetIds))
	for _, assetId := range assetIds {
		assetIdsString = append(assetIdsString, assetId.String())
	}

	return printJSON(map[string]any{
		"txid":      arkTxid,
		"asset_ids": assetIdsString,
	})
}

func reissue(ctx *cli.Context) error {
	controlAssetID := ctx.String(controlAssetIDFlag.Name)
	assetID := ctx.String(assetIDFlag.Name)
	amount := ctx.Uint64(amountFlag.Name)

	if controlAssetID == "" {
		return errors.New("control-asset-id is required")
	}
	if assetID == "" {
		return errors.New("asset-id is required")
	}
	if amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	arkTxid, err := arkSdkClient.ReissueAsset(ctx.Context, controlAssetID, assetID, amount)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"txid": arkTxid,
	})
}

func burn(ctx *cli.Context) error {
	amount := ctx.Uint64(amountFlag.Name)
	assetID := ctx.String(assetIDFlag.Name)

	if amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	arkTxid, err := arkSdkClient.BurnAsset(ctx.Context, assetID, amount)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"txid": arkTxid,
	})
}

func listVtxos(ctx *cli.Context) error {
	spendable, spent, err := arkSdkClient.ListVtxos(ctx.Context)
	if err != nil {
		return err
	}
	if ctx.Bool(spentFlag.Name) {
		return printJSON(spent)
	}
	return printJSON(spendable)
}

func getArkSdkClient(ctx *cli.Context) (arksdk.ArkClient, error) {
	dataDir := ctx.String(datadirFlag.Name)
	sdkRepository, err := store.NewStore(store.Config{
		ConfigStoreType: types.FileStore,
		BaseDir:         dataDir,
	})
	if err != nil {
		return nil, err
	}

	cfgData, err := sdkRepository.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	commandName := ctx.Args().First()
	if commandName != "init" && commandName != "version" && cfgData == nil {
		return nil, fmt.Errorf("CLI not initialized, run 'init' cmd to initialize")
	}

	opts := make([]arksdk.ClientOption, 0)
	if ctx.Bool(verboseFlag.Name) {
		opts = append(opts, arksdk.WithVerbose())
	}

	return loadOrCreateClient(
		arksdk.LoadArkClient, arksdk.NewArkClient, sdkRepository, opts,
	)
}

func loadOrCreateClient(
	loadFunc, newFunc func(types.Store, ...arksdk.ClientOption) (arksdk.ArkClient, error),
	sdkRepository types.Store, opts []arksdk.ClientOption,
) (arksdk.ArkClient, error) {
	client, err := loadFunc(sdkRepository, opts...)
	if err != nil {
		if errors.Is(err, arksdk.ErrNotInitialized) {
			return newFunc(sdkRepository, opts...)
		}
		return nil, err
	}
	return client, err
}

type receiverJSON struct {
	To     string      `json:"to"`
	Amount uint64      `json:"amount"`
	Assets []assetJSON `json:"assets"`
}

type assetJSON struct {
	AssetID string `json:"asset_id"`
	Amount  uint64 `json:"amount"`
}

func parseReceivers(receveirsJSON string) ([]types.Receiver, error) {
	list := make([]receiverJSON, 0)
	if err := json.Unmarshal([]byte(receveirsJSON), &list); err != nil {
		return nil, err
	}

	receivers := make([]types.Receiver, 0, len(list))
	for _, v := range list {
		assets := make([]types.Asset, 0, len(v.Assets))
		for _, asset := range v.Assets {
			assets = append(assets, types.Asset{
				AssetId: asset.AssetID, Amount: asset.Amount,
			})
		}

		receivers = append(receivers, types.Receiver{
			To: v.To, Amount: v.Amount, Assets: assets,
		})
	}
	return receivers, nil
}

func sendBitcoin(ctx *cli.Context, receivers []types.Receiver) error {
	var onchainReceivers, offchainReceivers []types.Receiver

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	if len(onchainReceivers) > 0 {
		txid, err := arkSdkClient.CollaborativeExit(
			ctx.Context, onchainReceivers[0].To, onchainReceivers[0].Amount,
		)
		if err != nil {
			return err
		}
		return printJSON(map[string]string{"txid": txid})
	}

	arkTxid, err := arkSdkClient.SendOffChain(ctx.Context, offchainReceivers)
	if err != nil {
		return err
	}
	return printJSON(map[string]string{"txid": arkTxid})
}

func readPassword(ctx *cli.Context) ([]byte, error) {
	password := []byte(ctx.String("password"))
	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}
	}
	return password, nil
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

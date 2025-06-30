package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/ark-network/ark/common"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
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
	)
	app.Flags = []cli.Flag{
		datadirFlag,
		networkFlag,
	}
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
		Value:    common.AppDataDir("ark-cli", false),
		EnvVars:  []string{DatadirEnvVar},
	}
	networkFlag = &cli.StringFlag{
		Name:  "network",
		Usage: "network to use mainnet, testnet, regtest, signet, mutinynet for bitcoin)",
		Value: "mainnet",
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
	zeroFeesFlag = &cli.BoolFlag{
		Name:    "zero-fees",
		Aliases: []string{"z"},
		Usage:   "UNSAFE: allow sending offchain transactions with zero fees, disable unilateral exit",
		Value:   false,
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
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize Ark wallet with encryption password, connect to Ark server",
		Action: func(ctx *cli.Context) error {
			return initArkSdk(ctx)
		},
		Flags: []cli.Flag{networkFlag, passwordFlag, privateKeyFlag, urlFlag, explorerFlag, restFlag},
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
		Flags: []cli.Flag{receiversFlag, toFlag, amountFlag, enableExpiryCoinselectFlag, passwordFlag, zeroFeesFlag},
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

	cfg := map[string]interface{}{
		"server_url":            cfgData.ServerUrl,
		"signer_pubkey":         hex.EncodeToString(cfgData.SignerPubKey.SerializeCompressed()),
		"wallet_type":           cfgData.WalletType,
		"client_type":           cfgData.ClientType,
		"network":               cfgData.Network.Name,
		"vtxo_tree_expiry":      cfgData.VtxoTreeExpiry,
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
	zeroFees := ctx.Bool(zeroFeesFlag.Name)
	if receiversJSON == "" && to == "" && amount == 0 {
		return fmt.Errorf("missing destination, use --to and --amount or --receivers")
	}

	var receivers []types.Receiver
	var err error
	if receiversJSON != "" {
		receivers, err = parseReceivers(receiversJSON)
		if err != nil {
			return err
		}
	} else {
		receivers = []types.Receiver{{To: to, Amount: amount}}
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	return sendCovenantLess(ctx, receivers, zeroFees)
}

func balance(ctx *cli.Context) error {
	computeExpiration := ctx.Bool(expiryDetailsFlag.Name)
	bal, err := arkSdkClient.Balance(ctx.Context, computeExpiration)
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
	computeExpiration := ctx.Bool(expiryDetailsFlag.Name)

	if force && complete {
		return fmt.Errorf("cannot use --force and --complete at the same time")
	}

	if force {
		return arkSdkClient.StartUnilateralExit(ctx.Context)
	}

	if complete {
		txID, err := arkSdkClient.CompleteUnilateralExit(ctx.Context, address)
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
		ctx.Context, address, amount, computeExpiration,
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

	txid, err := arkSdkClient.Settle(ctx.Context, arksdk.WithRecoverableVtxos)
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
	if commandName != "init" && cfgData == nil {
		return nil, fmt.Errorf("CLI not initialized, run 'init' cmd to initialize")
	}

	return loadOrCreateClient(
		arksdk.LoadArkClient, arksdk.NewArkClient, sdkRepository,
	)
}

func loadOrCreateClient(
	loadFunc, newFunc func(types.Store) (arksdk.ArkClient, error),
	sdkRepository types.Store,
) (arksdk.ArkClient, error) {
	client, err := loadFunc(sdkRepository)
	if err != nil {
		if errors.Is(err, arksdk.ErrNotInitialized) {
			return newFunc(sdkRepository)
		}
		return nil, err
	}
	return client, err
}

func parseReceivers(receveirsJSON string) ([]types.Receiver, error) {
	list := make([]map[string]interface{}, 0)
	if err := json.Unmarshal([]byte(receveirsJSON), &list); err != nil {
		return nil, err
	}

	receivers := make([]types.Receiver, 0, len(list))
	for _, v := range list {
		receivers = append(receivers, types.Receiver{
			To: v["to"].(string), Amount: uint64(v["amount"].(float64)),
		})
	}
	return receivers, nil
}

func sendCovenantLess(ctx *cli.Context, receivers []types.Receiver, withZeroFees bool) error {
	var onchainReceivers, offchainReceivers []types.Receiver

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	computeExpiration := ctx.Bool(enableExpiryCoinselectFlag.Name)
	if len(onchainReceivers) > 0 {
		txid, err := arkSdkClient.CollaborativeExit(
			ctx.Context, onchainReceivers[0].To, onchainReceivers[0].Amount, computeExpiration,
		)
		if err != nil {
			return err
		}
		return printJSON(map[string]string{"txid": txid})
	}

	arkTxid, err := arkSdkClient.SendOffChain(ctx.Context, computeExpiration, offchainReceivers)
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

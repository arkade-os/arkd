package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/config"
	grpcservice "github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/telemetry"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version will be set during build time
var Version string

const defaultWalletURL = "http://localhost:6060"

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "arkd-wallet"
	app.Usage = "run or manage the Ark Server wallet"
	app.UsageText = "Run the wallet with:\n\tarkd-wallet\n" +
		"Manage the wallet with:\n\tarkd-wallet command [command options]"
	app.Commands = append(
		app.Commands,
		startCmd,
		createCmd,
		restoreCmd,
		unlockCmd,
		statusCmd,
	)
	app.DefaultCommand = startCmd.Name

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

var (
	walletUrlFlag = &cli.StringFlag{
		Name:  "url",
		Usage: "the url where to reach the arkd-wallet gateway",
		Value: defaultWalletURL,
	}
	walletPasswordFlag = &cli.StringFlag{
		Name:     "password",
		Usage:    "wallet password",
		Required: true,
	}
	walletMnemonicFlag = &cli.StringFlag{
		Name:     "mnemonic",
		Usage:    "mnemonic from which to restore the wallet",
		Required: true,
	}
	walletGapLimitFlag = &cli.Uint64Flag{
		Name:  "addr-gap-limit",
		Usage: "address gap limit for wallet restoration",
		Value: 100,
	}

	startCmd = &cli.Command{
		Name:   "start",
		Usage:  "Run the arkd-wallet service",
		Action: startAction,
	}
	createCmd = &cli.Command{
		Name:   "create",
		Usage:  "Create a new wallet and unlock it",
		Action: createAction,
		Flags:  []cli.Flag{walletUrlFlag, walletPasswordFlag},
	}
	restoreCmd = &cli.Command{
		Name:   "restore",
		Usage:  "Restore the wallet from a mnemonic and unlock it",
		Action: restoreAction,
		Flags: []cli.Flag{
			walletUrlFlag, walletPasswordFlag, walletMnemonicFlag, walletGapLimitFlag,
		},
	}
	unlockCmd = &cli.Command{
		Name:   "unlock",
		Usage:  "Unlock the wallet",
		Action: unlockAction,
		Flags:  []cli.Flag{walletUrlFlag, walletPasswordFlag},
	}
	statusCmd = &cli.Command{
		Name:   "status",
		Usage:  "Get the status of the wallet",
		Action: statusAction,
		Flags:  []cli.Flag{walletUrlFlag},
	}
)

func startAction(_ *cli.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))
	if cfg.OtelCollectorEndpoint != "" {
		log.AddHook(telemetry.NewOTelHook())
	}

	svc, err := grpcservice.NewService(cfg)
	if err != nil {
		return fmt.Errorf("failed to create service: %s", err)
	}

	log.Infof("arkd wallet config: %+v", cfg)

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		return fmt.Errorf("failed to start service: %s", err)
	}
	log.Infof("arkd wallet listens on: %v", cfg.Port)

	// Stop the service at most once, whether triggered by the signal handler
	// below or by log.Exit/Fatal firing the registered exit handler.
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(svc.Stop) }
	log.RegisterExitHandler(stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(
		sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, os.Interrupt,
	)
	<-sigChan

	log.Info("shutting down service...")
	stop()
	return nil
}

// createAction generates a brand new wallet and unlocks it, talking directly to
// the arkd-wallet gateway. arkd does not manage the wallet lifecycle: each
// arkd-wallet must be set up this way out of band.
func createAction(ctx *cli.Context) error {
	baseURL := ctx.String("url")
	password := ctx.String("password")

	var seed struct {
		Seed string `json:"seed"`
	}
	if err := walletGet(baseURL, "/v1/wallet/seed", &seed); err != nil {
		return err
	}
	body, err := jsonBody(map[string]any{"seed": seed.Seed, "password": password})
	if err != nil {
		return err
	}
	if err := walletPost(baseURL, "/v1/wallet/create", body, nil); err != nil {
		return err
	}
	fmt.Println("IMPORTANT: store the following seed phrase securely and offline.")
	fmt.Println("Anyone with access to it can control this wallet and spend its funds.")
	fmt.Println(seed.Seed)

	return unlockWallet(baseURL, password)
}

// restoreAction restores a wallet from a mnemonic and unlocks it, talking
// directly to the arkd-wallet gateway. arkd does not manage the wallet
// lifecycle: each arkd-wallet must be set up this way out of band.
func restoreAction(ctx *cli.Context) error {
	baseURL := ctx.String("url")
	password := ctx.String("password")

	body, err := jsonBody(map[string]any{
		"seed":      ctx.String("mnemonic"),
		"password":  password,
		"gap_limit": ctx.Uint64("addr-gap-limit"),
	})
	if err != nil {
		return err
	}
	if err := walletPost(baseURL, "/v1/wallet/restore", body, nil); err != nil {
		return err
	}
	fmt.Println("wallet restored")

	return unlockWallet(baseURL, password)
}

func unlockAction(ctx *cli.Context) error {
	return unlockWallet(ctx.String("url"), ctx.String("password"))
}

// unlockWallet unlocks the wallet via the arkd-wallet gateway and prints
// confirmation. It is shared by the create, restore and unlock commands.
func unlockWallet(baseURL, password string) error {
	body, err := jsonBody(map[string]any{"password": password})
	if err != nil {
		return err
	}
	if err := walletPost(baseURL, "/v1/wallet/unlock", body, nil); err != nil {
		return err
	}
	fmt.Println("wallet unlocked")
	return nil
}

// jsonBody marshals a request body to JSON, escaping the values so a password or
// mnemonic containing quotes or backslashes can't corrupt the payload or inject
// extra fields.
func jsonBody(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to encode request body: %w", err)
	}
	return string(b), nil
}

func statusAction(ctx *cli.Context) error {
	var status struct {
		Initialized bool `json:"initialized"`
		Unlocked    bool `json:"unlocked"`
		Synced      bool `json:"synced"`
	}
	if err := walletGet(ctx.String("url"), "/v1/wallet/status", &status); err != nil {
		return err
	}
	fmt.Printf(
		"initialized: %t\nunlocked: %t\nsynced: %t\n",
		status.Initialized, status.Unlocked, status.Synced,
	)
	return nil
}

func walletGet(baseURL, path string, out any) error {
	resp, err := walletHTTPClient().Get(baseURL + path)
	if err != nil {
		return err
	}
	// nolint
	defer resp.Body.Close()
	return parseWalletResponse(resp, out)
}

func walletPost(baseURL, path, body string, out any) error {
	resp, err := walletHTTPClient().Post(
		baseURL+path, "application/json", bytes.NewReader([]byte(body)),
	)
	if err != nil {
		return err
	}
	// nolint
	defer resp.Body.Close()
	return parseWalletResponse(resp, out)
}

func walletHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func parseWalletResponse(resp *http.Response, out any) error {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(data))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

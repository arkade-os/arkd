package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
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
		Name:  "mnemonic",
		Usage: "mnemonic from which to restore the wallet (omit to create a new one)",
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
		Usage:  "Create (or restore) the wallet and unlock it",
		Action: createAction,
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

	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(
		sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, os.Interrupt,
	)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)

	return nil
}

// createAction creates a brand new wallet (or restores one from a mnemonic) and
// unlocks it, talking directly to the arkd-wallet gateway. arkd does not manage
// the wallet lifecycle: each arkd-wallet must be set up this way out of band.
func createAction(ctx *cli.Context) error {
	baseURL := ctx.String("url")
	password := ctx.String("password")
	mnemonic := ctx.String("mnemonic")

	if len(mnemonic) > 0 {
		body := fmt.Sprintf(
			`{"seed": "%s", "password": "%s", "gap_limit": %d}`,
			mnemonic, password, ctx.Uint64("addr-gap-limit"),
		)
		if err := walletPost(baseURL, "/v1/wallet/restore", body, nil); err != nil {
			return err
		}
		fmt.Println("wallet restored")
	} else {
		var seed struct {
			Seed string `json:"seed"`
		}
		if err := walletGet(baseURL, "/v1/wallet/seed", &seed); err != nil {
			return err
		}
		body := fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, password)
		if err := walletPost(baseURL, "/v1/wallet/create", body, nil); err != nil {
			return err
		}
		fmt.Println(seed.Seed)
	}

	body := fmt.Sprintf(`{"password": "%s"}`, password)
	if err := walletPost(baseURL, "/v1/wallet/unlock", body, nil); err != nil {
		return err
	}
	fmt.Println("wallet unlocked")
	return nil
}

func unlockAction(ctx *cli.Context) error {
	baseURL := ctx.String("url")
	body := fmt.Sprintf(`{"password": "%s"}`, ctx.String("password"))
	if err := walletPost(baseURL, "/v1/wallet/unlock", body, nil); err != nil {
		return err
	}
	fmt.Println("wallet unlocked")
	return nil
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

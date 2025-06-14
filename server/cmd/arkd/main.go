package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/config"
	grpcservice "github.com/ark-network/ark/server/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version will be set during build time
var Version string

const (
	macaroonDir  = "macaroons"
	macaroonFile = "admin.macaroon"
	tlsDir       = "tls"
	tlsCertFile  = "cert.pem"

	flagURL             = "url"
	flagDatadir         = "datadir"
	flagPassword        = "password"
	flagMnemonic        = "mnemonic"
	flagGapLimit        = "addr-gap-limit"
	flagAmount          = "amount"
	flagQuantity        = "quantity"
	flagWithdrawAmount  = "amount"
	flagWithdrawAddress = "address"
	flagRequestIds      = "ids"
)

// flags
var (
	urlFlag = &cli.StringFlag{
		Name:  flagURL,
		Usage: "the url where to reach ark server",
		Value: fmt.Sprintf("http://localhost:%d", config.DefaultPort),
	}
	datadirFlag = &cli.StringFlag{
		Name:  flagDatadir,
		Usage: "data directory of the ark server to source TLS cert and macaroon from if needed",
		Value: common.AppDataDir("arkd", false),
	}
)

func mainAction(_ *cli.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))

	svcConfig := grpcservice.Config{
		Datadir:         cfg.Datadir,
		Port:            cfg.Port,
		NoTLS:           cfg.NoTLS,
		NoMacaroons:     cfg.NoMacaroons,
		TLSExtraIPs:     cfg.TLSExtraIPs,
		TLSExtraDomains: cfg.TLSExtraDomains,
	}

	if cfg.AllowZeroFees {
		log.Warn("WARNING: AllowZeroFees is enabled")
	}

	svc, err := grpcservice.NewService(Version, svcConfig, cfg)
	if err != nil {
		return err
	}

	log.Infof("Ark Server config: %+v", cfg)

	log.Debug("starting service...")
	if err := svc.Start(); err != nil {
		return err
	}

	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan

	log.Debug("shutting down service...")
	log.Exit(0)

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "Arkd CLI"
	app.Usage = "arkd command line interface"
	app.Commands = append(app.Commands, walletCmd, queueCmd)
	app.Action = mainAction
	app.Flags = append(app.Flags, urlFlag, datadirFlag)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arkade-os/arkd/internal/config"
	grpcservice "github.com/arkade-os/arkd/internal/interface/grpc"
	"github.com/arkade-os/arkd/internal/telemetry"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version will be set during build time
var Version string

const (
	macaroonDir  = "macaroons"
	macaroonFile = "operator.macaroon"
	tlsDir       = "tls"
	tlsCertFile  = "cert.pem"
)

func mainAction(_ *cli.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))
	if cfg.OtelCollectorEndpoint != "" {
		log.AddHook(telemetry.NewOTelHook())
	}

	svcConfig := grpcservice.Config{
		Datadir:           cfg.Datadir,
		Port:              cfg.Port,
		AdminPort:         cfg.AdminPort,
		NoTLS:             cfg.NoTLS,
		NoMacaroons:       cfg.NoMacaroons,
		TLSExtraIPs:       cfg.TLSExtraIPs,
		TLSExtraDomains:   cfg.TLSExtraDomains,
		HeartbeatInterval: cfg.HeartbeatInterval,
	}

	svc, err := grpcservice.NewService(Version, svcConfig, cfg)
	if err != nil {
		return err
	}

	log.Infof("ark server config: %s", cfg)

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
	app.Name = "arkd"
	app.Usage = "run or manage the Ark Server"
	app.UsageText = "Run the Ark Server with:\n\tarkd\nManage the Ark Server with:\n\tarkd [global options] command [command options]"
	app.Commands = append(
		app.Commands,
		walletCmd,
		signerCmd,
		genkeyCmd,
		noteCmd,
		intentsCmd,
		scheduledSweepCmd,
		roundInfoCmd,
		roundsInTimeRangeCmd,
		scheduledSessionCmd,
		revokeAuthCmd,
	)
	app.Action = mainAction
	app.Flags = append(app.Flags, urlFlag, datadirFlag, macaroonFlag)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

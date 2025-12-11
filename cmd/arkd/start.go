package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/arkade-os/arkd/internal/config"
	grpcservice "github.com/arkade-os/arkd/internal/interface/grpc"
	"github.com/arkade-os/arkd/internal/telemetry"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Ark Server",
	Long:  `Start the Ark Server daemon to serve gRPC requests.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return startAction(nil)
	},
}

// startAction is a wrapper to a cobra command that starts the arkd server.
func startAction(_ *cli.Context) error {
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
		EnablePprof:       cfg.EnablePprof,
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

func init() {
	config.SetupFlags(startCmd)

	// TODO: Move this to the root cmd upon urfave/cli -> spf13/cobra migration.
	_ = viper.BindPFlags(startCmd.Flags())

	// Update the flag's Usage to display the corresponding env var name when --help is invoked.
	startCmd.Flags().VisitAll(func(f *pflag.Flag) {
		envVar := strings.ToUpper(envReplacer.Replace(f.Name))
		envUsage := fmt.Sprintf("[ARKD_%s]", envVar)

		if f.Usage == "" {
			f.Usage = envUsage
		} else {
			f.Usage = f.Usage + " " + envUsage
		}
	})
}

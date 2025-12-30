package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/config"
	grpcservice "github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/telemetry"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))
	if cfg.OtelCollectorEndpoint != "" {
		log.AddHook(telemetry.NewOTelHook())
	}

	svc, err := grpcservice.NewService(cfg)
	if err != nil {
		log.Fatalf("failed to create service: %s", err)
	}

	log.Infof("arkd wallet config: %+v", cfg)

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatalf("failed to start service: %s", err)
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
}

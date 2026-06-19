package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	Port                  = "PORT"
	LogLevel              = "LOG_LEVEL"
	SecretKey             = "SECRET_KEY"
	OtelCollectorEndpoint = "OTEL_COLLECTOR_ENDPOINT"
	OtelPushInterval      = "OTEL_PUSH_INTERVAL"
	PyroscopeServerURL    = "PYROSCOPE_SERVER_URL"

	defaultPort             = 6061
	defaultLogLevel         = int(log.InfoLevel)
	defaultOtelPushInterval = 10 // seconds
)

type Config struct {
	Port                  uint32
	LogLevel              int
	SecretKey             string
	OtelCollectorEndpoint string
	OtelPushInterval      int64
	PyroscopeServerURL    string

	SignerSvc application.Signer
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARKD_SIGNER")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(OtelPushInterval, defaultOtelPushInterval)

	cfg := &Config{
		Port:                  viper.GetUint32(Port),
		LogLevel:              viper.GetInt(LogLevel),
		SecretKey:             viper.GetString(SecretKey),
		OtelCollectorEndpoint: viper.GetString(OtelCollectorEndpoint),
		OtelPushInterval:      viper.GetInt64(OtelPushInterval),
		PyroscopeServerURL:    viper.GetString(PyroscopeServerURL),
	}

	if err := cfg.initServices(); err != nil {
		return nil, fmt.Errorf("error while initializing services: %s", err)
	}

	return cfg, nil
}

func (c *Config) initServices() error {
	if c.SecretKey == "" {
		return fmt.Errorf("missing signer secret key (ARKD_SIGNER_SECRET_KEY)")
	}
	buf, err := hex.DecodeString(c.SecretKey)
	if err != nil {
		return fmt.Errorf("invalid signer secret key format, must be hex")
	}
	prvkey, _ := btcec.PrivKeyFromBytes(buf)
	c.SignerSvc = application.New(prvkey)
	return nil
}

func (c *Config) String() string {
	clone := *c
	clone.SecretKey = "***"

	out, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return fmt.Sprintf("error while marshalling config JSON: %s", err)
	}
	return string(out)
}

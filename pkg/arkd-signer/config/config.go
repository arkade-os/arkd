package config

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	Port                  = "PORT"
	LogLevel              = "LOG_LEVEL"
	SecretKey             = "SECRET_KEY"
	DeprecatedKeys        = "DEPRECATED_KEYS"
	EmulatorComputeLimits = "EMULATOR_COMPUTE_LIMITS"

	defaultPort     = 6061
	defaultLogLevel = int(log.InfoLevel)
)

type Config struct {
	Port           uint32
	LogLevel       int
	SecretKey      string
	DeprecatedKeys string

	// never serialized: these hold the live operator key; keep them out of String()/JSON
	SignerSvc   application.Signer `json:"-"`
	EmulatorSvc emulator.Service   `json:"-"`

	ComputeLimits arkade.ComputeLimits
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARKD_SIGNER")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(LogLevel, defaultLogLevel)

	cfg := &Config{
		Port:           viper.GetUint32(Port),
		LogLevel:       viper.GetInt(LogLevel),
		SecretKey:      viper.GetString(SecretKey),
		DeprecatedKeys: viper.GetString(DeprecatedKeys),
		ComputeLimits:  parseComputeLimits(viper.GetString(EmulatorComputeLimits)),
	}

	if err := cfg.initServices(); err != nil {
		return nil, fmt.Errorf("error while initializing services: %w", err)
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
	if len(buf) != 32 {
		return fmt.Errorf("invalid signer secret key format, must be 32 bytes")
	}
	prvkey, _ := btcec.PrivKeyFromBytes(buf)

	deprecated, err := parseDeprecatedKeys(c.DeprecatedKeys)
	if err != nil {
		return err
	}

	currentPubkey := prvkey.PubKey().SerializeCompressed()
	for _, k := range deprecated {
		if bytes.Equal(k.Key.PubKey().SerializeCompressed(), currentPubkey) {
			return fmt.Errorf(
				"deprecated signer key %x matches the current signer key", currentPubkey,
			)
		}
	}

	c.SignerSvc = application.New(prvkey, deprecated)

	// Build []*btcec.PrivateKey for the emulator (strips the cutoff metadata).
	deprecatedPrivKeys := make([]*btcec.PrivateKey, 0, len(deprecated))
	for _, d := range deprecated {
		deprecatedPrivKeys = append(deprecatedPrivKeys, d.Key)
	}

	emulatorSvc, err := emulator.New(
		context.Background(),
		prvkey,
		deprecatedPrivKeys,
		prvkey.PubKey(), // arkdPubKey = our own operator pubkey (signing-only mode)
		nil,             // finalizer: nil => signing-only
		c.ComputeLimits,
	)
	if err != nil {
		return fmt.Errorf("failed to init emulator service: %w", err)
	}
	c.EmulatorSvc = emulatorSvc

	return nil
}

func (c *Config) String() string {
	clone := *c
	clone.SecretKey = "***"
	clone.DeprecatedKeys = "***"

	out, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return fmt.Sprintf("error while marshalling config JSON: %s", err)
	}
	return string(out)
}

// parseComputeLimits parses the ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS env var.
// An empty string returns DefaultComputeLimits(). Non-empty values must be a
// comma-separated list of "OPCODE=limit" pairs, e.g. "OP_CHECKSIG=10,OP_ECMUL=5".
// Unrecognised opcode names are silently ignored so the service stays forward-compatible.
func parseComputeLimits(raw string) arkade.ComputeLimits {
	limits := arkade.DefaultComputeLimits()
	if raw == "" {
		return limits
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, valueStr, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		valueStr = strings.TrimSpace(valueStr)
		val, err := strconv.Atoi(valueStr)
		if err != nil || val < 0 {
			continue
		}
		opcode, found := arkade.OpcodeByName[name]
		if !found {
			continue
		}
		limits[opcode] = val
	}
	return limits
}

// parseDeprecatedKeys parses a comma-separated list of hex-encoded private keys,
// each optionally followed by a cutoff date: "<hexkey>[:<unix timestamp>]". The
// cutoff date is the time after which the key is no longer accepted, 0 if unset.
func parseDeprecatedKeys(raw string) ([]application.DeprecatedSignerKey, error) {
	keys := make([]application.DeprecatedSignerKey, 0)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		keyPart, cutoffPart, hasCutoff := strings.Cut(entry, ":")
		if strings.TrimSpace(keyPart) == "" {
			return nil, fmt.Errorf("invalid signer key entry, missing hex key: %s", entry)
		}

		buf, err := hex.DecodeString(keyPart)
		if err != nil {
			return nil, fmt.Errorf("invalid signer key format, must be hex: %s", keyPart)
		}
		if len(buf) != 32 {
			return nil, fmt.Errorf("invalid signer key format")
		}
		key, _ := btcec.PrivKeyFromBytes(buf)

		var cutoffDate int64
		if hasCutoff {
			cutoff, err := strconv.ParseInt(cutoffPart, 10, 64)
			if err != nil || cutoff < 0 {
				return nil, fmt.Errorf(
					"invalid cutoff date, must be a positive unix timestamp: %s", entry,
				)
			}
			cutoffDate = cutoff
		}

		keys = append(keys, application.DeprecatedSignerKey{Key: key, CutoffDate: cutoffDate})
	}
	return keys, nil
}

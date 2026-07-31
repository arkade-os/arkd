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

	computeLimits, err := parseComputeLimits(viper.GetString(EmulatorComputeLimits))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Port:           viper.GetUint32(Port),
		LogLevel:       viper.GetInt(LogLevel),
		SecretKey:      viper.GetString(SecretKey),
		DeprecatedKeys: viper.GetString(DeprecatedKeys),
		ComputeLimits:  computeLimits,
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
	prvkey, err := privKeyFromBytes(buf)
	if err != nil {
		return fmt.Errorf("invalid signer secret key, %w", err)
	}

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

	// Build []*btcec.PrivateKey for the emulator. The cutoff dates are dropped
	// because emulator.New takes bare keys and the library has no cutoff concept,
	// so a deprecated key stays usable on the ArkadeScript path after the date
	// that retires it on the application.Signer path. Honouring cutoffs here
	// needs the emulator API to carry them; do not "fix" this by filtering
	// expired keys at load time, since the process would then keep whatever set
	// it started with until restart.
	deprecatedPrivKeys := make([]*btcec.PrivateKey, 0, len(deprecated))
	for _, d := range deprecated {
		deprecatedPrivKeys = append(deprecatedPrivKeys, d.Key)
	}

	emulatorSvc, err := emulator.New(
		context.Background(),
		prvkey,
		deprecatedPrivKeys,
		prvkey.PubKey(), // arkdPubKey = our own operator pubkey (signing-only mode)
		// Untyped nil selects signing-only. Keep it untyped: emulator.New
		// panics on a typed nil Finalizer holding a nil pointer.
		nil,
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
//
// Every malformed entry is a startup error rather than a warning. This var only
// exists to tighten a DoS-relevant VM guard, so skipping a typo would leave the
// much larger default in place, which is the opposite of what the operator
// asked for, and a log line is far too easy to miss.
func parseComputeLimits(raw string) (arkade.ComputeLimits, error) {
	limits := arkade.DefaultComputeLimits()
	if raw == "" {
		return limits, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, valueStr, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("invalid compute limit %q: expected OPCODE=limit", entry)
		}
		name = strings.TrimSpace(name)
		valueStr = strings.TrimSpace(valueStr)
		val, err := strconv.Atoi(valueStr)
		if err != nil || val < 0 {
			return nil, fmt.Errorf(
				"invalid compute limit %q: value must be a non-negative integer", entry,
			)
		}
		opcode, found := arkade.OpcodeByName[name]
		if !found {
			return nil, fmt.Errorf("invalid compute limit %q: unknown opcode %q", entry, name)
		}
		limits[opcode] = val
	}
	return limits, nil
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
		key, err := privKeyFromBytes(buf)
		if err != nil {
			return nil, fmt.Errorf("invalid signer key %s, %w", keyPart, err)
		}

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

// privKeyFromBytes rejects what btcec.PrivKeyFromBytes silently accepts. That
// helper reduces the input mod N and cannot fail, so an all-zero key yields a
// pubkey at infinity and an out-of-range one becomes a different key than the
// operator configured. Either way the signer boots and every signature it
// produces is invalid, so fail at config load instead.
func privKeyFromBytes(buf []byte) (*btcec.PrivateKey, error) {
	var scalar btcec.ModNScalar
	if overflow := scalar.SetByteSlice(buf); overflow || scalar.IsZero() {
		return nil, fmt.Errorf("must be a scalar in [1, N-1] for secp256k1")
	}
	return btcec.PrivKeyFromScalar(&scalar), nil
}

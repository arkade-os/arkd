package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	Port                  = "PORT"
	LogLevel              = "LOG_LEVEL"
	SecretKey             = "SECRET_KEY"
	DeprecatedKeys        = "DEPRECATED_KEYS"
	OtelCollectorEndpoint = "OTEL_COLLECTOR_ENDPOINT"

	defaultPort     = 6061
	defaultLogLevel = int(log.InfoLevel)
)

type Config struct {
	Port                  uint32
	LogLevel              int
	OtelCollectorEndpoint string

	SignerSvc *application.Signer `json:"-"`
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARKD_SIGNER")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(LogLevel, defaultLogLevel)

	signerSvc, err := newSigner(viper.GetString(SecretKey), viper.GetString(DeprecatedKeys))
	if err != nil {
		return nil, fmt.Errorf("error while initializing services: %s", err)
	}

	return &Config{
		Port:                  viper.GetUint32(Port),
		LogLevel:              viper.GetInt(LogLevel),
		OtelCollectorEndpoint: viper.GetString(OtelCollectorEndpoint),
		SignerSvc:             signerSvc,
	}, nil
}

func newSigner(secretKey, deprecatedKeys string) (*application.Signer, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("missing signer secret key (ARKD_SIGNER_SECRET_KEY)")
	}
	prvkey, err := parsePrivKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signer secret key, %w", err)
	}

	deprecated, err := parseDeprecatedKeys(deprecatedKeys)
	if err != nil {
		return nil, err
	}

	currentPubkey := prvkey.PubKey().SerializeCompressed()
	for _, k := range deprecated {
		if bytes.Equal(k.Key.PubKey().SerializeCompressed(), currentPubkey) {
			return nil, fmt.Errorf(
				"deprecated signer key %x matches the current signer key", currentPubkey,
			)
		}
	}

	return application.New(prvkey, deprecated), nil
}

func (c *Config) String() string {
	out, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("error while marshalling config JSON: %s", err)
	}
	return string(out)
}

// parseDeprecatedKeys parses "<hexkey>[:<unix cutoff>],...".
func parseDeprecatedKeys(raw string) ([]application.DeprecatedSignerKey, error) {
	keys := make([]application.DeprecatedSignerKey, 0)
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		keyPart, cutoffPart, hasCutoff := strings.Cut(entry, ":")
		if strings.TrimSpace(keyPart) == "" {
			return nil, fmt.Errorf("invalid deprecated signer key #%d, missing hex key", i)
		}

		key, err := parsePrivKey(keyPart)
		if err != nil {
			return nil, fmt.Errorf("invalid deprecated signer key #%d, %w", i, err)
		}

		var cutoffDate int64
		if hasCutoff {
			cutoff, err := strconv.ParseInt(cutoffPart, 10, 64)
			if err != nil || cutoff < 0 {
				return nil, fmt.Errorf(
					"invalid deprecated signer key #%d, cutoff must be a positive unix time", i,
				)
			}
			cutoffDate = cutoff
		}

		keys = append(keys, application.DeprecatedSignerKey{Key: key, CutoffDate: cutoffDate})
	}
	return keys, nil
}

// btcec.PrivKeyFromBytes silently reduces mod N, so zero and out-of-range keys
// must be rejected here.
func parsePrivKey(hexKey string) (*btcec.PrivateKey, error) {
	buf, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("must be hex")
	}
	if len(buf) != 32 {
		return nil, fmt.Errorf("must be 32 bytes")
	}
	var scalar btcec.ModNScalar
	if overflow := scalar.SetByteSlice(buf); overflow || scalar.IsZero() {
		return nil, fmt.Errorf("must be a scalar in [1, N-1] for secp256k1")
	}
	return btcec.PrivKeyFromScalar(&scalar), nil
}

package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application/scanner"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application/wallet"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/infrastructure/cypher"
	db "github.com/arkade-os/arkd/pkg/arkd-wallet/core/infrastructure/db/badger"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/infrastructure/nbxplorer"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	Port                  = "PORT"
	Datadir               = "DATADIR"
	LogLevel              = "LOG_LEVEL"
	Network               = "NETWORK"
	NbxplorerURL          = "NBXPLORER_URL"
	SignerKey             = "SIGNER_KEY"
	DeprecatedSignerKeys  = "DEPRECATED_SIGNER_KEYS"
	OtelCollectorEndpoint = "OTEL_COLLECTOR_ENDPOINT"
	OtelPushInterval      = "OTEL_PUSH_INTERVAL"
	PyroscopeServerURL    = "PYROSCOPE_SERVER_URL"

	defaultPort             = 6060
	defaultLogLevel         = int(log.InfoLevel)
	defaultDatadir          = arklib.AppDataDir("arkd-wallet", false)
	defaultNetwork          = "bitcoin"
	defaultOtelPushInterval = 10 // seconds
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARKD_WALLET")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(Network, defaultNetwork)
	viper.SetDefault(OtelPushInterval, defaultOtelPushInterval)

	net, err := getNetwork()
	if err != nil {
		return nil, fmt.Errorf("error while getting network: %s", err)
	}

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	dbPath := filepath.Join(viper.GetString(Datadir), "db")
	if err := makeDirectoryIfNotExists(dbPath); err != nil {
		return nil, fmt.Errorf("failed to create db dir: %s", err)
	}

	cfg := &Config{
		Port:                  viper.GetUint32(Port),
		DbDir:                 dbPath,
		LogLevel:              viper.GetInt(LogLevel),
		Network:               net,
		NbxplorerURL:          viper.GetString(NbxplorerURL),
		SignerKey:             viper.GetString(SignerKey),
		DeprecatedSignerKeys:  viper.GetString(DeprecatedSignerKeys),
		OtelCollectorEndpoint: viper.GetString(OtelCollectorEndpoint),
		OtelPushInterval:      viper.GetInt64(OtelPushInterval),
		PyroscopeServerURL:    viper.GetString(PyroscopeServerURL),
	}

	if err := cfg.initServices(); err != nil {
		return nil, fmt.Errorf("error while initializing services: %s", err)
	}

	return cfg, nil
}

type Config struct {
	Port                  uint32
	DbDir                 string
	LogLevel              int
	Network               arklib.Network
	NbxplorerURL          string
	SignerKey             string
	DeprecatedSignerKeys  string
	OtelCollectorEndpoint string
	OtelPushInterval      int64
	PyroscopeServerURL    string

	WalletSvc  application.WalletService
	ScannerSvc application.BlockchainScanner
}

func (c *Config) String() string {
	clone := *c

	json, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return fmt.Sprintf("error while marshalling config JSON: %s", err)
	}
	return string(json)
}

func (c *Config) initServices() error {
	var signerKey *btcec.PrivateKey
	if c.SignerKey != "" {
		buf, err := hex.DecodeString(c.SignerKey)
		if err != nil {
			return fmt.Errorf("invalid signer key format, must be hex")
		}
		signerKey, _ = btcec.PrivKeyFromBytes(buf)
	}

	deprecatedSignerKeys, err := parseDeprecatedSignerKeys(c.DeprecatedSignerKeys)
	if err != nil {
		return err
	}

	repository, err := db.NewSeedRepository(c.DbDir, nil)
	if err != nil {
		return fmt.Errorf("error while creating seed repository: %s", err)
	}

	cryptoSvc := cypher.New()

	nbxplorerSvc, err := nbxplorer.New(c.NbxplorerURL)
	if err != nil {
		return err
	}

	network, err := getNetwork()
	if err != nil {
		return fmt.Errorf("error while getting network: %s", err)
	}

	walletSvc := wallet.New(wallet.WalletOptions{
		SeedRepository:       repository,
		Cypher:               cryptoSvc,
		Nbxplorer:            nbxplorerSvc,
		Network:              network.Name,
		SignerKey:            signerKey,
		DeprecatedSignerKeys: deprecatedSignerKeys,
	})

	scannerSvc, err := scanner.New(nbxplorerSvc, network.Name)
	if err != nil {
		return fmt.Errorf("error while creating scanner: %w", err)
	}

	c.WalletSvc = walletSvc
	c.ScannerSvc = scannerSvc
	return nil
}

func initDatadir() error {
	datadir := viper.GetString(Datadir)
	return makeDirectoryIfNotExists(datadir)
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0755)
	}
	return nil
}

func getNetwork() (arklib.Network, error) {
	switch strings.ToLower(viper.GetString(Network)) {
	case arklib.Bitcoin.Name:
		return arklib.Bitcoin, nil
	case arklib.BitcoinTestNet.Name:
		return arklib.BitcoinTestNet, nil
	case arklib.BitcoinTestNet4.Name:
		return arklib.BitcoinTestNet4, nil
	case arklib.BitcoinSigNet.Name:
		return arklib.BitcoinSigNet, nil
	case arklib.BitcoinMutinyNet.Name:
		return arklib.BitcoinMutinyNet, nil
	case arklib.BitcoinRegTest.Name:
		return arklib.BitcoinRegTest, nil
	default:
		return arklib.Network{}, fmt.Errorf("unknown network %s", viper.GetString(Network))
	}
}

// parseDeprecatedSignerKeys parses a comma-separated list of hex-encoded private
// keys, each optionally followed by a cutoff date: "<hexkey>[:<unix timestamp>]".
// The cutoff date is the time after which the key is no longer accepted, 0 if unset.
func parseDeprecatedSignerKeys(raw string) ([]wallet.DeprecatedSignerKey, error) {
	keys := make([]wallet.DeprecatedSignerKey, 0)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		keyPart, cutoffPart, hasCutoff := strings.Cut(entry, ":")
		if strings.TrimSpace(keyPart) == "" {
			return nil, fmt.Errorf("invalid signer key entry, missing hex key: %s", entry)
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

		buf, err := hex.DecodeString(keyPart)
		if err != nil {
			return nil, fmt.Errorf("invalid signer key format, must be hex: %s", keyPart)
		}
		key, _ := btcec.PrivKeyFromBytes(buf)
		keys = append(keys, wallet.DeprecatedSignerKey{Key: key, CutoffDate: cutoffDate})
	}
	return keys, nil
}

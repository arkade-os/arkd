package config

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func delay(v uint32) arklib.RelativeLocktime {
	lt, _ := arklib.ParseRelativeLocktime(v)
	return lt
}

// validConfig returns a config that passes every early Validate() check and
// produces valid settings. Tests mutate a copy to exercise a single failure.
func validConfig() Config {
	return Config{
		EventDbType:                   "badger",
		DbType:                        "sqlite",
		TxBuilderType:                 "covenantless",
		IndexerExposure:               "public",
		MaxConcurrentStreams:          1,
		SessionDuration:               30,
		UnrolledVtxoMinExpiryMargin:   30,
		BanThreshold:                  0,
		BanDuration:                   60,
		SettlementMinExpiryGap:        60,
		VtxoNoCsvValidationCutoffDate: 0,
		RoundMinParticipantsCount:     1,
		RoundMaxParticipantsCount:     10,
		VtxoMinAmount:                 1,
		VtxoMaxAmount:                 -1,
		UtxoMinAmount:                 1,
		UtxoMaxAmount:                 -1,
		UnilateralExitDelay:           delay(512),
		PublicUnilateralExitDelay:     delay(512),
		CheckpointExitDelay:           delay(1024),
		BoardingExitDelay:             delay(1536),
		VtxoTreeExpiry:                delay(1024),
		MaxTxWeight:                   400000,
		MaxOpReturnOutputs:            3,
		AssetTxMaxWeightRatio:         0.5,
		NoteUriPrefix:                 "",
	}
}

func TestSupportedTypeSupports(t *testing.T) {
	st := supportedType{"sqlite": {}, "postgres": {}}

	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{"known type is supported", "sqlite", true},
		{"another known type is supported", "postgres", true},
		{"unknown type is not supported", "mysql", false},
		{"empty string is not supported", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, st.supports(tt.query))
		})
	}
}

func TestConfigGetSettings(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("maps config into domain settings", func(t *testing.T) {
			c := validConfig()

			settings, err := c.getSettings()
			require.NoError(t, err)
			require.NotNil(t, settings)

			// Config values are mapped into the domain settings (durations are seconds).
			require.Equal(t, 30*time.Second, settings.SessionDuration)
			require.Equal(t, int64(1), settings.RoundMinParticipantsCount)
			require.Equal(t, int64(10), settings.RoundMaxParticipantsCount)
			require.Equal(t, delay(512), settings.UnilateralExitDelay)
			require.Equal(t, float32(0.5), settings.AssetTxMaxWeightRatio)
		})

		t.Run("result is memoized", func(t *testing.T) {
			c := validConfig()

			first, err := c.getSettings()
			require.NoError(t, err)

			// A later change to the config does not affect the cached settings.
			c.SessionDuration = 9999
			second, err := c.getSettings()
			require.NoError(t, err)

			require.Same(t, first, second)
			require.Equal(t, 30*time.Second, second.SessionDuration)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			mutate      func(c *Config)
			errContains string
		}{
			{
				"zero session duration",
				func(c *Config) { c.SessionDuration = 0 },
				"invalid session duration",
			},
			{
				"zero vtxo min amount",
				func(c *Config) { c.VtxoMinAmount = 0 },
				"vtxo min amount must be greater than 0",
			},
			{
				"max participants below min",
				func(c *Config) {
					c.RoundMinParticipantsCount = 5
					c.RoundMaxParticipantsCount = 2
				},
				"batch max participants count must be >= min participants count",
			},
			{
				"asset tx max weight ratio out of range",
				func(c *Config) { c.AssetTxMaxWeightRatio = 1.5 },
				"asset tx max weight ratio must be in range",
			},
			{
				"mismatched locktime types",
				func(c *Config) { c.UnilateralExitDelay = delay(256) }, // block while others seconds
				"unilateral exit delay and vtxo tree expiry type mismatch",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := validConfig()
				tt.mutate(&c)

				settings, err := c.getSettings()
				require.ErrorContains(t, err, tt.errContains)
				require.Nil(t, settings)
			})
		}
	})
}

// TestConfigValidateEarlyChecks covers the validation that runs before any
// service is constructed. The valid path is not unit-testable here because it
// builds real services (wallet, db, ...); that belongs to integration tests.
func TestConfigValidateEarlyChecks(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			mutate      func(c *Config)
			errContains string
		}{
			{
				"unsupported event db type",
				func(c *Config) { c.EventDbType = "mongo" },
				"event db type not supported",
			},
			{
				"unsupported db type",
				func(c *Config) { c.DbType = "mysql" },
				"db type not supported",
			},
			{
				"unsupported tx builder type",
				func(c *Config) { c.TxBuilderType = "covenant" },
				"tx builder type not supported",
			},
			{
				"unsupported unlocker type",
				func(c *Config) { c.UnlockerType = "hsm" },
				"unlocker type not supported",
			},
			{
				"unsupported live store type",
				func(c *Config) { c.LiveStoreType = "memcached" },
				"live store type not supported",
			},
			{
				"unsupported indexer exposure type",
				func(c *Config) { c.IndexerExposure = "secret" },
				"indexer exposure type not supported",
			},
			{
				"non-public exposure without auth token expiry",
				func(c *Config) {
					c.IndexerExposure = "private"
					c.IndexerAuthTokenExpiry = 0
				},
				"indexer auth token expiry must be greater than 0",
			},
			{
				"non-public exposure without signing key",
				func(c *Config) {
					c.IndexerExposure = "private"
					c.IndexerAuthTokenExpiry = 3600
					c.IndexerSigningKey = ""
				},
				"indexer signing key is required",
			},
			{
				"invalid settings",
				func(c *Config) { c.SessionDuration = 0 },
				"invalid session duration",
			},
			{
				"zero max concurrent streams",
				func(c *Config) { c.MaxConcurrentStreams = 0 },
				"max concurrent streams must be greater than 0",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := validConfig()
				tt.mutate(&c)
				require.ErrorContains(t, c.Validate(), tt.errContains)
			})
		}
	})
}

func TestConfigStringRedactsSecrets(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *Config)
		value    string
		redacted bool
	}{
		{
			"unlocker password is redacted",
			func(c *Config) { c.UnlockerPassword = "super-secret-password" },
			"super-secret-password",
			true,
		},
		{
			"indexer signing key is redacted",
			func(c *Config) { c.IndexerSigningKey = "deadbeefsigningkey" },
			"deadbeefsigningkey",
			true,
		},
		{
			"non-sensitive field is preserved",
			func(c *Config) { c.WalletAddr = "localhost:6060" },
			"localhost:6060",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)

			out := c.String()
			if tt.redacted {
				require.NotContains(t, out, tt.value)
				require.Contains(t, out, "••••••")
			} else {
				require.Contains(t, out, tt.value)
			}
		})
	}
}

func TestParseWalletFallbackAddrs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "localhost:6061", []string{"localhost:6061"}},
		{"multiple", "a:6060,b:6060,c:6060", []string{"a:6060", "b:6060", "c:6060"}},
		{"trims whitespace", "a:6060, b:6060 ,c:6060", []string{"a:6060", "b:6060", "c:6060"}},
		{"drops empty entries", "a:6060,,b:6060,", []string{"a:6060", "b:6060"}},
		{"only separators", " , , ", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseWalletFallbackAddrs(tt.raw))
		})
	}
}

// fakeFallbackWallet is a ports.WalletService that only implements Close; via
// the embedded nil interface every other method is unused by these tests.
type fakeFallbackWallet struct {
	ports.WalletService
	closed *int
}

func (f *fakeFallbackWallet) Close() { *f.closed++ }

func TestDialFallbackWallets(t *testing.T) {
	orig := newWalletClient
	t.Cleanup(func() { newWalletClient = orig })

	regtest := &arklib.Network{Name: "regtest"}
	testnet := &arklib.Network{Name: "testnet"}

	t.Run("all on the same network", func(t *testing.T) {
		var closes int
		newWalletClient = func(_, _ string) (ports.WalletService, *arklib.Network, error) {
			return &fakeFallbackWallet{closed: &closes}, regtest, nil
		}

		c := &Config{network: regtest, WalletFallbackAddrs: []string{"a:6060", "b:6060"}}
		fbs, err := c.dialFallbackWallets()

		require.NoError(t, err)
		require.Len(t, fbs, 2)
		require.Zero(t, closes)
	})

	t.Run("network mismatch hard-fails and closes dialed", func(t *testing.T) {
		var closes, calls int
		newWalletClient = func(_, _ string) (ports.WalletService, *arklib.Network, error) {
			calls++
			net := regtest
			if calls == 2 {
				net = testnet
			}
			return &fakeFallbackWallet{closed: &closes}, net, nil
		}

		c := &Config{network: regtest, WalletFallbackAddrs: []string{"a:6060", "b:6060"}}
		fbs, err := c.dialFallbackWallets()

		require.Error(t, err)
		require.Nil(t, fbs)
		require.Contains(t, err.Error(), "b:6060")
		require.Contains(t, err.Error(), "testnet")
		require.Contains(t, err.Error(), "regtest")
		// The mismatched wallet and the previously dialed one are both closed.
		require.Equal(t, 2, closes)
	})

	t.Run("dial error hard-fails and closes dialed", func(t *testing.T) {
		var closes, calls int
		newWalletClient = func(_, _ string) (ports.WalletService, *arklib.Network, error) {
			calls++
			if calls == 2 {
				return nil, nil, fmt.Errorf("connection refused")
			}
			return &fakeFallbackWallet{closed: &closes}, regtest, nil
		}

		c := &Config{network: regtest, WalletFallbackAddrs: []string{"a:6060", "b:6060"}}
		fbs, err := c.dialFallbackWallets()

		require.Error(t, err)
		require.Nil(t, fbs)
		require.Contains(t, err.Error(), "b:6060")
		// The first, successfully dialed fallback is closed.
		require.Equal(t, 1, closes)
	})
}

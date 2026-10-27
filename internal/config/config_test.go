package config

import (
	"math"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func TestSupportedTypeSupports(t *testing.T) {
	st := supportedType{"postgres": {}}

	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{"known type is supported", "postgres", true},
		{"removed type is unsupported", "sqlite", false},
		{"unknown type is not supported", "mysql", false},
		{"empty string is not supported", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, st.supports(tt.query))
		})
	}
}

func TestStorageTypes(t *testing.T) {
	require.True(t, supportedDbs.supports("postgres"))
	require.True(t, supportedEventDbs.supports("postgres"))
	require.True(t, supportedLiveStores.supports("redis"))
	for _, removed := range []string{"sqlite", "badger", "inmemory"} {
		require.False(t, supportedDbs.supports(removed))
		require.False(t, supportedEventDbs.supports(removed))
		require.False(t, supportedLiveStores.supports(removed))
	}
}

func TestConfigGetSettings(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("maps config into domain settings", func(t *testing.T) {
			c := testConfig()

			settings, err := c.getSettings()
			require.NoError(t, err)
			require.NotNil(t, settings)

			// Config values are mapped into the domain settings (durations are seconds).
			require.Equal(t, 30*time.Second, settings.SessionDuration)
			require.Equal(t, 5*time.Minute, settings.FinalizationLockTTL)
			require.Equal(t, int64(1), settings.RoundMinParticipantsCount)
			require.Equal(t, int64(10), settings.RoundMaxParticipantsCount)
			require.Equal(t, delay(512), settings.UnilateralExitDelay)
			require.Equal(t, float32(0.5), settings.AssetTxMaxWeightRatio)
		})

		t.Run("result is memoized", func(t *testing.T) {
			c := testConfig()

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
				c := testConfig()
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
			{
				"zero finalization lock TTL",
				func(c *Config) { c.FinalizationLockTTL = 0 },
				"finalization lock TTL must be positive",
			},
			{
				"negative finalization lock TTL",
				func(c *Config) { c.FinalizationLockTTL = -1 },
				"finalization lock TTL must be positive",
			},
			{
				"overflowing finalization lock TTL",
				func(c *Config) { c.FinalizationLockTTL = math.MaxInt64 },
				"finalization lock TTL is too large",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := testConfig()
				tt.mutate(&c)
				require.ErrorContains(t, c.Validate(), tt.errContains)
			})
		}
	})
}

func TestConfigString(t *testing.T) {
	t.Run("redacted", func(t *testing.T) {
		tests := []struct {
			name    string
			mutate  func(c *Config)
			secrets []string
			kept    []string
		}{
			{
				name:    "unlocker password",
				mutate:  func(c *Config) { c.UnlockerPassword = "super-secret-password" },
				secrets: []string{"super-secret-password"},
				kept:    []string{redactedValue},
			},
			{
				name:    "indexer signing key",
				mutate:  func(c *Config) { c.IndexerSigningKey = "deadbeefsigningkey" },
				secrets: []string{"deadbeefsigningkey"},
				kept:    []string{redactedValue},
			},
			{
				name: "url credentials",
				mutate: func(c *Config) {
					c.DbUrl = "postgres://arkd:sup3rs3cr3t@db.internal:5432/projection?sslmode=verify-full"
					c.EventDbUrl = "postgres://arkd:ev3nts3cr3t@db.internal:5432/event?sslmode=verify-full"
					c.RedisUrl = "redis://default:r3diss3cr3t@cache.internal:6379/0"
				},
				secrets: []string{"sup3rs3cr3t", "ev3nts3cr3t", "r3diss3cr3t"},
				// Non-sensitive parts stay readable so the logged config is still useful.
				kept: []string{
					"arkd:redacted@db.internal:5432", "projection", "sslmode=verify-full",
					"default:redacted@cache.internal:6379",
				},
			},
			{
				name: "url secret query params",
				mutate: func(c *Config) {
					c.DbUrl = "postgres://arkd@db.internal:5432/projection?password=qp4rams3cr3t&sslmode=verify-full"
					c.EventDbUrl = "postgres://arkd@db.internal:5432/event?sslpassword=k3ys3cr3t"
				},
				secrets: []string{"qp4rams3cr3t", "k3ys3cr3t"},
				kept:    []string{"db.internal:5432", "projection", "sslmode=verify-full"},
			},
			{
				name:    "keyword dsn",
				mutate:  func(c *Config) { c.DbUrl = "host=db.internal user=arkd password=kw0rds3cr3t dbname=projection" },
				secrets: []string{"host=db.internal user=arkd password=kw0rds3cr3t dbname=projection"},
				kept:    []string{`"DbUrl": "` + redactedValue + `"`},
			},
			{
				name:    "dsn with missing scheme",
				mutate:  func(c *Config) { c.DbUrl = "://broken" },
				secrets: []string{"://broken"},
				kept:    []string{`"DbUrl": "` + redactedValue + `"`},
			},
			{
				name:    "dsn with invalid percent escape",
				mutate:  func(c *Config) { c.DbUrl = "%%%" },
				secrets: []string{"%%%"},
				kept:    []string{`"DbUrl": "` + redactedValue + `"`},
			},
			{
				name:    "dsn with unterminated ipv6 host",
				mutate:  func(c *Config) { c.DbUrl = "http://[::1" },
				secrets: []string{"http://[::1"},
				kept:    []string{`"DbUrl": "` + redactedValue + `"`},
			},
			{
				name:    "dsn with space in password",
				mutate:  func(c *Config) { c.DbUrl = "postgres://arkd:pa ss@db.internal:5432/projection" },
				secrets: []string{"postgres://arkd:pa ss@db.internal:5432/projection"},
				kept:    []string{`"DbUrl": "` + redactedValue + `"`},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := testConfig()
				tt.mutate(&c)

				out := c.String()
				for _, secret := range tt.secrets {
					require.NotContains(t, out, secret, "secret leaked into Config.String()")
				}
				for _, kept := range tt.kept {
					require.Contains(t, out, kept)
				}
			})
		}
	})

	t.Run("not redacted", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(c *Config)
			kept   []string
		}{
			{
				name:   "non-sensitive field",
				mutate: func(c *Config) { c.WalletAddr = "localhost:6060" },
				kept:   []string{"localhost:6060"},
			},
			{
				name:   "passwordless dsn",
				mutate: func(c *Config) { c.DbUrl = "postgres://arkd@db.internal:5432/projection?sslmode=verify-full" },
				kept:   []string{"postgres://arkd@db.internal:5432/projection?sslmode=verify-full"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := testConfig()
				tt.mutate(&c)

				out := c.String()
				for _, kept := range tt.kept {
					require.Contains(t, out, kept)
				}
			})
		}
	})
}

// validConfig returns a config that passes every early Validate() check and
// produces valid settings. Tests mutate a copy to exercise a single failure.
func testConfig() Config {
	return Config{
		EventDbType:                   "postgres",
		DbType:                        "postgres",
		TxBuilderType:                 "covenantless",
		IndexerExposure:               "public",
		MaxConcurrentStreams:          1,
		FinalizationLockTTL:           300,
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

func delay(v uint32) arklib.RelativeLocktime {
	lt, _ := arklib.ParseRelativeLocktime(v)
	return lt
}

package config_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-signer/config"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigRequiresSecretKey(t *testing.T) {
	t.Setenv("ARKD_SIGNER_SECRET_KEY", "")
	_, err := config.LoadConfig()
	require.Error(t, err)
}

func TestLoadConfigParsesSecretKey(t *testing.T) {
	t.Setenv("ARKD_SIGNER_SECRET_KEY",
		"afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0")
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.SignerSvc)
	require.EqualValues(t, 6061, cfg.Port)
}

func TestComputeLimits(t *testing.T) {
	const secret = "afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0"
	checksig := arkade.OpcodeByName["OP_CHECKSIG"]

	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
		cfg, err := config.LoadConfig()
		require.NoError(t, err)
		require.Equal(t, arkade.DefaultComputeLimits()[checksig], cfg.ComputeLimits[checksig])
	})

	t.Run("valid limit applied", func(t *testing.T) {
		t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
		t.Setenv("ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS", "OP_CHECKSIG=7")
		cfg, err := config.LoadConfig()
		require.NoError(t, err)
		require.Equal(t, 7, cfg.ComputeLimits[checksig])
	})

	t.Run("multiple limits applied", func(t *testing.T) {
		ecmul, ok := arkade.OpcodeByName["OP_ECMUL"]
		require.True(t, ok)

		t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
		t.Setenv("ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS", "OP_CHECKSIG=7,OP_ECMUL=5")
		cfg, err := config.LoadConfig()
		require.NoError(t, err)
		require.Equal(t, 7, cfg.ComputeLimits[checksig])
		require.Equal(t, 5, cfg.ComputeLimits[ecmul])
	})

	// This var exists only to tighten a DoS-relevant guard, so a typo must not
	// silently leave the larger default in place.
	t.Run("misconfiguration fails startup", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{"non-integer value", "OP_CHECKSIG=notanumber"},
			{"negative value", "OP_CHECKSIG=-1"},
			{"unknown opcode", "OP_NOPE=3,OP_CHECKSIG=9"},
			{"missing equals", "OP_CHECKSIG"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
				t.Setenv("ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS", tc.raw)
				_, err := config.LoadConfig()
				require.ErrorContains(t, err, "compute limit")
			})
		}
	})
}

// btcec.PrivKeyFromBytes reduces its input mod N and cannot fail, so without an
// explicit scalar check these all load a signer that produces invalid
// signatures for the rest of the process lifetime.
func TestLoadConfigRejectsInvalidScalars(t *testing.T) {
	const curveN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"all zero", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"curve order", curveN},
		{"above curve order", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ARKD_SIGNER_SECRET_KEY", tc.key)
			_, err := config.LoadConfig()
			require.ErrorContains(t, err, "scalar")
		})
	}

	t.Run("deprecated key is checked too", func(t *testing.T) {
		t.Setenv("ARKD_SIGNER_SECRET_KEY",
			"afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0")
		t.Setenv("ARKD_SIGNER_DEPRECATED_KEYS",
			"0000000000000000000000000000000000000000000000000000000000000000")
		_, err := config.LoadConfig()
		require.ErrorContains(t, err, "scalar")
	})
}

func TestConfigStringRedactsSecrets(t *testing.T) {
	secretKey := "afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0"
	deprecatedKey := "1111111111111111111111111111111111111111111111111111111111111111"
	t.Setenv("ARKD_SIGNER_SECRET_KEY", secretKey)
	t.Setenv("ARKD_SIGNER_DEPRECATED_KEYS", deprecatedKey)

	cfg, err := config.LoadConfig()
	require.NoError(t, err)

	out := cfg.String()
	require.NotContains(t, out, secretKey)
	require.NotContains(t, out, deprecatedKey)
	require.Contains(t, out, "***")
	require.Contains(t, out, "6061") // non-sensitive field preserved
}

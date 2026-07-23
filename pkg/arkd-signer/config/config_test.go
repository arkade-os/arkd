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

	t.Run("malformed value keeps default", func(t *testing.T) {
		t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
		t.Setenv("ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS", "OP_CHECKSIG=notanumber")
		cfg, err := config.LoadConfig()
		require.NoError(t, err)
		require.Equal(t, arkade.DefaultComputeLimits()[checksig], cfg.ComputeLimits[checksig])
	})

	t.Run("unknown opcode ignored, valid ones still applied", func(t *testing.T) {
		t.Setenv("ARKD_SIGNER_SECRET_KEY", secret)
		t.Setenv("ARKD_SIGNER_EMULATOR_COMPUTE_LIMITS", "OP_NOPE=3,OP_CHECKSIG=9")
		cfg, err := config.LoadConfig()
		require.NoError(t, err)
		require.Equal(t, 9, cfg.ComputeLimits[checksig])
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

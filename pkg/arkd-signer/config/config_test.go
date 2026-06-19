package config_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-signer/config"
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

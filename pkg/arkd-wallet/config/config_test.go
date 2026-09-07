package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{
		Port:         6060,
		DbDir:        "/tmp/arkd-wallet/db",
		LogLevel:     4,
		NbxplorerURL: "http://localhost:32838",
	}
}

func TestConfigStringRedactsSecrets(t *testing.T) {
	const signerKey = "1111111111111111111111111111111111111111111111111111111111111111"
	const deprecatedKey = "2222222222222222222222222222222222222222222222222222222222222222"

	tests := []struct {
		name           string
		mutate         func(c *Config)
		mustNotContain string
		mustContain    string
	}{
		{
			name:           "signer key is redacted",
			mutate:         func(c *Config) { c.SignerKey = signerKey },
			mustNotContain: signerKey,
			mustContain:    redactedMask,
		},
		{
			name:           "deprecated signer keys are redacted",
			mutate:         func(c *Config) { c.DeprecatedSignerKeys = deprecatedKey + ":1767926037" },
			mustNotContain: deprecatedKey,
			mustContain:    redactedMask,
		},
		{
			name:        "unset signer key stays empty rather than looking configured",
			mutate:      func(c *Config) { c.SignerKey = "" },
			mustContain: `"SignerKey": ""`,
		},
		{
			name:        "non-sensitive field is preserved",
			mutate:      func(c *Config) { c.NbxplorerURL = "http://nbxplorer:32838" },
			mustContain: "http://nbxplorer:32838",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)

			out := c.String()
			if tt.mustNotContain != "" {
				require.NotContains(t, out, tt.mustNotContain)
			}
			require.Contains(t, out, tt.mustContain)
		})
	}
}

// services would leak once any gains an exported field
func TestConfigStringOmitsServices(t *testing.T) {
	c := validConfig()

	out := c.String()

	require.NotContains(t, out, "WalletSvc")
	require.NotContains(t, out, "ScannerSvc")
}

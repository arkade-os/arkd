package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigString(t *testing.T) {
	t.Run("redacted", func(t *testing.T) {
		tests := []struct {
			name    string
			mutate  func(c *Config)
			secrets []string
			kept    []string
		}{
			{
				name:    "url credentials",
				mutate:  func(c *Config) { c.NbxplorerURL = "http://nbxuser:nbxp4ss@nbxplorer:24444" },
				secrets: []string{"nbxp4ss"},
				// Non-sensitive parts stay readable so the logged config is still useful.
				kept: []string{"nbxuser:redacted@nbxplorer:24444", "/app/data"},
			},
			{
				name:    "url with missing scheme",
				mutate:  func(c *Config) { c.NbxplorerURL = "://broken" },
				secrets: []string{"://broken"},
				kept:    []string{`"NbxplorerURL": "` + redactedValue + `"`},
			},
			{
				name:    "url with invalid percent escape",
				mutate:  func(c *Config) { c.NbxplorerURL = "%%%" },
				secrets: []string{"%%%"},
				kept:    []string{`"NbxplorerURL": "` + redactedValue + `"`},
			},
			{
				name:    "url with unterminated ipv6 host",
				mutate:  func(c *Config) { c.NbxplorerURL = "http://[::1" },
				secrets: []string{"http://[::1"},
				kept:    []string{`"NbxplorerURL": "` + redactedValue + `"`},
			},
			{
				name:    "bare host url",
				mutate:  func(c *Config) { c.NbxplorerURL = "nbxplorer" },
				secrets: []string{"nbxplorer"},
				kept:    []string{`"NbxplorerURL": "` + redactedValue + `"`},
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
			absent []string
		}{
			{
				name:   "credentialless url",
				mutate: func(c *Config) { c.NbxplorerURL = "http://nbxplorer:24444" },
				kept:   []string{"http://nbxplorer:24444"},
			},
			{
				name:   "services are omitted",
				mutate: func(*Config) {},
				absent: []string{"WalletSvc", "ScannerSvc"},
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
				for _, absent := range tt.absent {
					require.NotContains(t, out, absent)
				}
			})
		}
	})
}

// testConfig returns a config without secrets. Tests mutate a copy to exercise a single
// field.
func testConfig() Config {
	return Config{Port: 6060, DbDir: "/app/data"}
}

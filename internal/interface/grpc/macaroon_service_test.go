package grpcservice

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewMacaroonService covers both service startup paths: with and without macaroons.
// Although such unit tests already exist in the macaroon package, we repeat them to ensure
// there's no dependency version mismatch in between.
func TestNewMacaroonService(t *testing.T) {
	tests := []struct {
		name        string
		noMacaroons bool
		// To mock a restart of the service
		reopen    bool
		expectSvc bool
	}{
		{
			name:        "macaroons enabled",
			noMacaroons: false,
			expectSvc:   true,
		},
		{
			name:        "macaroons enabled on existing db",
			noMacaroons: false,
			reopen:      true,
			expectSvc:   true,
		},
		{
			name:        "macaroons disabled",
			noMacaroons: true,
			expectSvc:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Datadir:     t.TempDir(),
				NoMacaroons: tt.noMacaroons,
			}

			if tt.reopen {
				svc, db, err := newMacaroonService(cfg)
				require.NoError(t, err)
				// Reopening below only succeeds if it actually released the bolt file lock.
				closeMacaroonStore(svc, db)
			}

			svc, db, err := newMacaroonService(cfg)
			require.NoError(t, err)

			t.Cleanup(func() { closeMacaroonStore(svc, db) })

			dbPath := filepath.Join(cfg.Datadir, macaroonsDbFile)

			if !tt.expectSvc {
				require.Nil(t, svc)
				require.Nil(t, db)
				require.NoFileExists(t, dbPath)
				return
			}

			require.NotNil(t, svc)
			require.NotNil(t, db)
			require.FileExists(t, dbPath)

			require.NoError(t, svc.Close())
			require.NoError(t, db.Close())
		})
	}
}

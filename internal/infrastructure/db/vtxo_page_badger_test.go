package db_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/stretchr/testify/require"
)

// TestService only covers sqlite and postgres, and badger is the one backend
// that filters, sorts and pages in Go rather than in sql. Running the shared
// suite against it holds that Go path to the same contract, and checks its
// filter against the suite's own copy on every run.
func TestVtxosWithPubKeysPageBadger(t *testing.T) {
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "badger",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir(), nil},
		Settings:         validSettings(),
	}, nil)
	require.NoError(t, err)
	defer svc.Close()

	testVtxosWithPubKeysPage(t, svc)
}

package store_test

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var (
	key, _         = btcec.NewPrivateKey()
	forfeitkKey, _ = btcec.NewPrivateKey()
	testConfigData = types.Config{
		ServerUrl:           "127.0.0.1:7070",
		SignerPubKey:        key.PubKey(),
		ForfeitPubKey:       forfeitkKey.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		Network:             arklib.BitcoinRegTest,
		SessionDuration:     10,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		Dust:                1000,
		BoardingExitDelay:   arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		ForfeitAddress:      "bcrt1qzvqj",
		CheckpointTapscript: "abcdefghijklmnopqrtuvxyz",
	}
)

func TestService(t *testing.T) {
	t.Run("config store", func(t *testing.T) {
		dbDir := t.TempDir()
		tests := []struct {
			name   string
			config store.Config
		}{
			{
				name: "inmemory",
				config: store.Config{
					ConfigStoreType: types.InMemoryStore,
				},
			},
			{
				name: "file",
				config: store.Config{
					ConfigStoreType: types.FileStore,
					BaseDir:         dbDir,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, err := store.NewStore(tt.config)
				require.NoError(t, err)
				testConfigStore(t, svc.ConfigStore())
			})
		}
	})
}

func testConfigStore(t *testing.T, storeSvc types.ConfigStore) {
	ctx := context.Background()

	// Check empty data when store is empty.
	data, err := storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Nil(t, data)

	// Check no side effects when cleaning an empty store.
	err = storeSvc.CleanData(ctx)
	require.NoError(t, err)

	// Check add and retrieve data.
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)

	data, err = storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Equal(t, testConfigData, *data)

	// Check clean and retrieve data.
	err = storeSvc.CleanData(ctx)
	require.NoError(t, err)

	data, err = storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Nil(t, data)

	// Check overwriting the store.
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)
}

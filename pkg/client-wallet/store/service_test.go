package store_test

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-wallet/store"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var (
	key, _           = btcec.NewPrivateKey()
	forfeitkKey, _   = btcec.NewPrivateKey()
	deprecatedKey, _ = btcec.NewPrivateKey()
	cutoffDate       = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	testConfigData   = clientlib.ServerParams{
		ServerUrl:           "127.0.0.1:7070",
		SignerPubKey:        key.PubKey(),
		ForfeitPubKey:       forfeitkKey.PubKey(),
		Network:             arklib.BitcoinRegTest,
		SessionDuration:     10,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		Dust:                1000,
		BoardingExitDelay:   arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		ForfeitAddress:      "bcrt1qzvqj",
		CheckpointTapscript: "abcdefghijklmnopqrtuvxyz",
		DeprecatedSigners:   []clientlib.DeprecatedSigner{},
		Digest:              "digest",
	}
)

func TestStoreAddData(t *testing.T) {
	forEach(t, func(t *testing.T, storeSvc types.Store) {
		t.Run("valid", func(t *testing.T) {
			ctx := t.Context()

			// Check empty data when store is empty.
			data, err := storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Nil(t, data)

			// Check add and retrieve data.
			err = storeSvc.AddData(ctx, testConfigData)
			require.NoError(t, err)

			data, err = storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Equal(t, testConfigData, *data)

			// Check deprecated signers are persisted and restored.
			configWithDeprecatedSigners := testConfigData
			configWithDeprecatedSigners.DeprecatedSigners = []clientlib.DeprecatedSigner{
				{
					PubKey:     deprecatedKey.PubKey(),
					CutoffDate: cutoffDate,
				},
			}
			err = storeSvc.AddData(ctx, configWithDeprecatedSigners)
			require.NoError(t, err)

			data, err = storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Equal(t, configWithDeprecatedSigners, *data)

			// Check overwriting the store.
			err = storeSvc.AddData(ctx, testConfigData)
			require.NoError(t, err)
			err = storeSvc.AddData(ctx, testConfigData)
			require.NoError(t, err)
		})
	})
}

func forEach(t *testing.T, fn func(t *testing.T, storeSvc types.Store)) {
	t.Helper()

	tests := []struct {
		name      string
		storeType string
		datadir   string
	}{
		{
			name:      "inmemory",
			storeType: types.InMemoryStore,
		},
		{
			name:      "file",
			storeType: types.FileStore,
			datadir:   t.TempDir(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := store.NewStore(tt.storeType, tt.datadir)
			require.NoError(t, err)
			require.NotNil(t, svc)
			fn(t, svc)
		})
	}
}

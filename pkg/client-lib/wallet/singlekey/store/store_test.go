package store_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	filestore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWalletStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	testWalletData := walletstore.WalletData{
		EncryptedPrvkey: make([]byte, 32),
		PasswordHash:    make([]byte, 32),
		PubKey:          key.PubKey(),
	}

	tests := []struct {
		name string
		args []interface{}
	}{
		{
			name: types.InMemoryStore,
		},
		{
			name: types.FileStore,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			var storeSvc walletstore.WalletStore
			var err error
			if tt.name == types.InMemoryStore {
				storeSvc, err = inmemorystore.NewWalletStore()
			} else {
				storeSvc, err = filestore.NewWalletStore(t.TempDir())
			}
			require.NoError(t, err)
			require.NotNil(t, storeSvc)

			// Check empty data when store is empty.
			walletData, err := storeSvc.GetWallet()
			require.NoError(t, err)
			require.Nil(t, walletData)

			// Check add and retrieve data.
			err = storeSvc.AddWallet(testWalletData)
			require.NoError(t, err)

			walletData, err = storeSvc.GetWallet()
			require.NoError(t, err)
			require.Equal(t, testWalletData, *walletData)

			// Check overwriting the store.
			err = storeSvc.AddWallet(testWalletData)
			require.NoError(t, err)
		})
	}
}

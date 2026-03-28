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

func TestBoardingDescriptors(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: types.InMemoryStore},
		{name: types.FileStore},
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

			// Empty store returns empty slice.
			descriptors, err := storeSvc.GetBoardingDescriptors()
			require.NoError(t, err)
			require.Empty(t, descriptors)

			// Add a descriptor and retrieve it.
			d1 := walletstore.BoardingDescriptor{
				Address:    "tb1p_custom_addr_1",
				Tapscripts: []string{"aabb", "ccdd"},
			}
			err = storeSvc.AddBoardingDescriptor(d1)
			require.NoError(t, err)

			descriptors, err = storeSvc.GetBoardingDescriptors()
			require.NoError(t, err)
			require.Len(t, descriptors, 1)
			require.Equal(t, d1, descriptors[0])

			// Adding the same address is a no-op.
			err = storeSvc.AddBoardingDescriptor(d1)
			require.NoError(t, err)

			descriptors, err = storeSvc.GetBoardingDescriptors()
			require.NoError(t, err)
			require.Len(t, descriptors, 1)

			// Add a second descriptor.
			d2 := walletstore.BoardingDescriptor{
				Address:    "tb1p_custom_addr_2",
				Tapscripts: []string{"eeff"},
			}
			err = storeSvc.AddBoardingDescriptor(d2)
			require.NoError(t, err)

			descriptors, err = storeSvc.GetBoardingDescriptors()
			require.NoError(t, err)
			require.Len(t, descriptors, 2)
			require.Equal(t, d1, descriptors[0])
			require.Equal(t, d2, descriptors[1])
		})
	}
}

package identitystore_test

import (
	"testing"

	identitystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store"
	identityfilestore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/file"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWalletStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	testData := identitystore.IdentityData{
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
			var storeSvc identitystore.IdentityStore
			var err error
			if tt.name == types.InMemoryStore {
				storeSvc, err = identityinmemorystore.NewStore()
			} else {
				storeSvc, err = identityfilestore.NewStore(t.TempDir())
			}
			require.NoError(t, err)
			require.NotNil(t, storeSvc)

			// Check empty data when store is empty.
			data, err := storeSvc.Get()
			require.NoError(t, err)
			require.Nil(t, data)

			// Check add and retrieve data.
			err = storeSvc.Add(testData)
			require.NoError(t, err)

			data, err = storeSvc.Get()
			require.NoError(t, err)
			require.Equal(t, testData, *data)

			// Check overwriting the store.
			err = storeSvc.Add(testData)
			require.NoError(t, err)
		})
	}
}

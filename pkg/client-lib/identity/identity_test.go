package identity_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	singlekeyidentity "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const testPassword = "password"

var network = chaincfg.RegressionNetParams

func TestCreate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc := newTestIdentity(t)
		seed, err := identitySvc.Create(t.Context(), network, testPassword, "")
		require.NoError(t, err)
		require.NotEmpty(t, seed)
	})
}

func TestLockUnlock(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("lock and unlock", func(t *testing.T) {
			identitySvc, _ := newUnlockedTestIdentity(t)
			ctx := t.Context()

			require.False(t, identitySvc.IsLocked())

			err := identitySvc.Lock(ctx)
			require.NoError(t, err)
			require.True(t, identitySvc.IsLocked())

			_, err = identitySvc.Unlock(ctx, testPassword)
			require.NoError(t, err)
			require.False(t, identitySvc.IsLocked())
		})

		t.Run("unlock when already unlocked", func(t *testing.T) {
			identitySvc, _ := newUnlockedTestIdentity(t)
			alreadyUnlocked, err := identitySvc.Unlock(t.Context(), "")
			require.NoError(t, err)
			require.True(t, alreadyUnlocked)
		})

		t.Run("lock when already locked", func(t *testing.T) {
			identitySvc, _ := newUnlockedTestIdentity(t)
			err := identitySvc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, identitySvc.IsLocked())

			err = identitySvc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, identitySvc.IsLocked())
		})
	})
}

func TestGetKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc, seed := newUnlockedTestIdentity(t)
		key, err := identitySvc.GetKey(t.Context(), "")
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, key.PubKey)

		prvkeyBytes, err := hex.DecodeString(seed)
		require.NoError(t, err)
		expectedPrvkey, _ := btcec.PrivKeyFromBytes(prvkeyBytes)
		require.True(t, key.PubKey.IsEqual(expectedPrvkey.PubKey()))
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(t *testing.T) identity.Identity
			expErr string
		}{
			{
				"not initialized",
				func(t *testing.T) identity.Identity { return newTestIdentity(t) },
				"identity not initialized",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key, err := tt.setup(t).GetKey(t.Context(), "")
				require.ErrorContains(t, err, tt.expErr)
				require.Nil(t, key)
			})
		}
	})
}

func TestNewKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc, seed := newUnlockedTestIdentity(t)
		key, err := identitySvc.NewKey(t.Context())
		require.NoError(t, err)
		require.NotNil(t, key.PubKey)

		prvkeyBytes, err := hex.DecodeString(seed)
		require.NoError(t, err)
		expectedPrvkey, _ := btcec.PrivKeyFromBytes(prvkeyBytes)
		require.True(t, key.PubKey.IsEqual(expectedPrvkey.PubKey()))
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(t *testing.T) identity.Identity
			expErr string
		}{
			{
				"not initialized",
				func(t *testing.T) identity.Identity { return newTestIdentity(t) },
				"identity not initialized",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key, err := tt.setup(t).NewKey(t.Context())
				require.ErrorContains(t, err, tt.expErr)
				require.Nil(t, key)
			})
		}
	})
}

func TestNextKeyId(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc, _ := newUnlockedTestIdentity(t)
		ctx := t.Context()

		// Single-key identity always returns "m" regardless of the id argument.
		id, err := identitySvc.NextKeyId(ctx, "")
		require.NoError(t, err)
		require.Equal(t, "m", id)

		id, err = identitySvc.NextKeyId(ctx, "some-arbitrary-id")
		require.NoError(t, err)
		require.Equal(t, "m", id)
	})
}

func TestGetKeyIndex(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc, _ := newUnlockedTestIdentity(t)
		ctx := t.Context()

		// Single-key identity always returns 0 regardless of the id argument.
		idx, err := identitySvc.GetKeyIndex(ctx, "")
		require.NoError(t, err)
		require.Equal(t, uint32(0), idx)

		idx, err = identitySvc.GetKeyIndex(ctx, "some-arbitrary-id")
		require.NoError(t, err)
		require.Equal(t, uint32(0), idx)
	})
}

func TestListKeys(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		identitySvc, seed := newUnlockedTestIdentity(t)

		keys, err := identitySvc.ListKeys(t.Context())
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.NotNil(t, keys[0].PubKey)

		prvkeyBytes, err := hex.DecodeString(seed)
		require.NoError(t, err)
		expectedPrvkey, _ := btcec.PrivKeyFromBytes(prvkeyBytes)
		require.True(t, keys[0].PubKey.IsEqual(expectedPrvkey.PubKey()))
	})
}

func TestClaimKey(t *testing.T) {
	t.Run("not initialized", func(t *testing.T) {
		svc := newTestIdentity(t)
		err := svc.ClaimKey(t.Context(), "anything")
		require.Error(t, err)
	})

	t.Run("initialized is a no op", func(t *testing.T) {
		svc, _ := newUnlockedTestIdentity(t)
		require.NoError(t, svc.ClaimKey(t.Context(), "anything"))
		require.NoError(t, svc.ClaimKey(t.Context(), "anything")) // idempotent

		keys, err := svc.ListKeys(t.Context())
		require.NoError(t, err)
		require.Len(t, keys, 1) // singlekey always reports its one key
	})
}

func newTestIdentity(t *testing.T) identity.Identity {
	t.Helper()
	store, err := identityinmemorystore.NewStore()
	require.NoError(t, err)
	identitySvc, err := singlekeyidentity.NewIdentity(store)
	require.NoError(t, err)
	return identitySvc
}

func newUnlockedTestIdentity(t *testing.T) (identity.Identity, string) {
	t.Helper()
	identitySvc := newTestIdentity(t)
	ctx := t.Context()
	seed, err := identitySvc.Create(ctx, network, testPassword, "")
	require.NoError(t, err)
	_, err = identitySvc.Unlock(ctx, testPassword)
	require.NoError(t, err)
	return identitySvc, seed
}

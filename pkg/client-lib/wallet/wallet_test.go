package wallet_test

import (
	"encoding/hex"
	"testing"

	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	inmemorywalletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	"github.com/stretchr/testify/require"
)

const testPassword = "password"

func TestCreate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		walletSvc := newTestWallet(t)
		seed, err := walletSvc.Create(t.Context(), testPassword, "")
		require.NoError(t, err)
		require.NotEmpty(t, seed)
	})
}

func TestLockUnlock(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("lock and unlock", func(t *testing.T) {
			walletSvc, _ := newUnlockedTestWallet(t)
			ctx := t.Context()

			require.False(t, walletSvc.IsLocked())

			err := walletSvc.Lock(ctx)
			require.NoError(t, err)
			require.True(t, walletSvc.IsLocked())

			_, err = walletSvc.Unlock(ctx, testPassword)
			require.NoError(t, err)
			require.False(t, walletSvc.IsLocked())
		})

		t.Run("unlock when already unlocked", func(t *testing.T) {
			walletSvc, _ := newUnlockedTestWallet(t)
			alreadyUnlocked, err := walletSvc.Unlock(t.Context(), "")
			require.NoError(t, err)
			require.True(t, alreadyUnlocked)
		})

		t.Run("lock when already locked", func(t *testing.T) {
			walletSvc, _ := newUnlockedTestWallet(t)
			err := walletSvc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, walletSvc.IsLocked())

			err = walletSvc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, walletSvc.IsLocked())
		})
	})
}

func TestGetKeyPair(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		walletSvc, seed := newUnlockedTestWallet(t)
		prvkey, pubkey, err := walletSvc.GetKeyPair(t.Context(), "")
		require.NoError(t, err)
		require.NotNil(t, prvkey)
		require.NotNil(t, pubkey)
		require.Equal(t, seed, hex.EncodeToString(prvkey.Serialize()))
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(t *testing.T) wallet.WalletService
			expErr string
		}{
			{
				"not initialized",
				func(t *testing.T) wallet.WalletService { return newTestWallet(t) },
				"wallet not initialized",
			},
			{
				"locked",
				func(t *testing.T) wallet.WalletService {
					w := newTestWallet(t)
					_, err := w.Create(t.Context(), testPassword, "")
					require.NoError(t, err)
					return w
				},
				"wallet is locked",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				prvkey, pubkey, err := tt.setup(t).GetKeyPair(t.Context(), "")
				require.ErrorContains(t, err, tt.expErr)
				require.Nil(t, prvkey)
				require.Nil(t, pubkey)
			})
		}
	})
}

func TestNewKeyPair(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		walletSvc, seed := newUnlockedTestWallet(t)
		prvkey, pubkey, err := walletSvc.NewKeyPair(t.Context())
		require.NoError(t, err)
		require.NotNil(t, prvkey)
		require.NotNil(t, pubkey)
		require.Equal(t, seed, hex.EncodeToString(prvkey.Serialize()))
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(t *testing.T) wallet.WalletService
			expErr string
		}{
			{
				"not initialized",
				func(t *testing.T) wallet.WalletService { return newTestWallet(t) },
				"wallet not initialized",
			},
			{
				"locked",
				func(t *testing.T) wallet.WalletService {
					w := newTestWallet(t)
					_, err := w.Create(t.Context(), testPassword, "")
					require.NoError(t, err)
					return w
				},
				"wallet is locked",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				prvkey, pubkey, err := tt.setup(t).NewKeyPair(t.Context())
				require.ErrorContains(t, err, tt.expErr)
				require.Nil(t, prvkey)
				require.Nil(t, pubkey)
			})
		}
	})
}

func newTestWallet(t *testing.T) wallet.WalletService {
	t.Helper()
	store, err := inmemorystore.NewConfigStore()
	require.NoError(t, err)
	walletStore, err := inmemorywalletstore.NewWalletStore()
	require.NoError(t, err)
	walletSvc, err := singlekeywallet.NewBitcoinWallet(store, walletStore)
	require.NoError(t, err)
	return walletSvc
}

func newUnlockedTestWallet(t *testing.T) (wallet.WalletService, string) {
	t.Helper()
	walletSvc := newTestWallet(t)
	ctx := t.Context()
	seed, err := walletSvc.Create(ctx, testPassword, "")
	require.NoError(t, err)
	_, err = walletSvc.Unlock(ctx, testPassword)
	require.NoError(t, err)
	return walletSvc, seed
}

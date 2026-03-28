package wallet_test

import (
	"context"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/store/inmemory"
	sdktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	inmemorywalletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWallet(t *testing.T) {
	ctx := context.Background()
	key, _ := btcec.NewPrivateKey()
	password := "password"
	testStoreData := sdktypes.Config{
		ServerUrl:           "127.0.0.1:7070",
		SignerPubKey:        key.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		Network:             arklib.BitcoinRegTest,
		SessionDuration:     10,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		Dust:                1000,
		BoardingExitDelay:   arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		ForfeitAddress:      "bcrt1qzvqj",
		CheckpointTapscript: "",
	}
	tests := []struct {
		name  string
		chain string
		args  []interface{}
	}{
		{
			name:  "bitcoin" + wallet.SingleKeyWallet,
			chain: "bitcoin",
			args:  []interface{}{arklib.BitcoinRegTest},
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			store, err := inmemorystore.NewConfigStore()
			require.NoError(t, err)
			require.NotNil(t, store)

			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)

			walletStore, err := inmemorywalletstore.NewWalletStore()
			require.NoError(t, err)
			require.NotNil(t, walletStore)

			walletSvc, err := singlekeywallet.NewBitcoinWallet(store, walletStore)
			require.NoError(t, err)
			require.NotNil(t, walletSvc)

			key, err := walletSvc.Create(ctx, password, "")
			require.NoError(t, err)
			require.NotEmpty(t, key)

			onchainAddr, offchainAddr, boardingAddr, err := walletSvc.NewAddress(ctx, false)
			require.NoError(t, err)
			require.NotEmpty(t, offchainAddr)
			require.NotEmpty(t, onchainAddr)
			require.NotEmpty(t, boardingAddr)

			onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := walletSvc.GetAddresses(
				ctx,
			)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, 1)
			require.Len(t, onchainAddrs, 1)
			require.Len(t, redemptionAddrs, 1)
			require.Len(t, boardingAddrs, 1)

			onchainAddr, offchainAddr, boardingAddr, err = walletSvc.NewAddress(ctx, true)
			require.NoError(t, err)
			require.NotEmpty(t, offchainAddr)
			require.NotEmpty(t, onchainAddr)
			require.NotEmpty(t, boardingAddr)

			expectedNumOfAddresses := 2
			if strings.Contains(tt.name, wallet.SingleKeyWallet) {
				expectedNumOfAddresses = 1
			}

			onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err = walletSvc.GetAddresses(
				ctx,
			)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, expectedNumOfAddresses)
			require.Len(t, onchainAddrs, expectedNumOfAddresses)
			require.Len(t, redemptionAddrs, expectedNumOfAddresses)
			require.Len(t, boardingAddrs, expectedNumOfAddresses)

			num := 3
			onchainAddrs, offchainAddrs, boardingAddrs, err = walletSvc.NewAddresses(
				ctx,
				false,
				num,
			)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, num)
			require.Len(t, boardingAddrs, num)
			require.Len(t, onchainAddrs, num)

			expectedNumOfAddresses += num
			if strings.Contains(tt.name, wallet.SingleKeyWallet) {
				expectedNumOfAddresses = 1
			}
			onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err = walletSvc.GetAddresses(
				ctx,
			)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, expectedNumOfAddresses)
			require.Len(t, onchainAddrs, expectedNumOfAddresses)
			require.Len(t, redemptionAddrs, expectedNumOfAddresses)
			require.Len(t, boardingAddrs, expectedNumOfAddresses)

			// Check no password is required to unlock if wallet is already unlocked.
			alreadyUnlocked, err := walletSvc.Unlock(ctx, password)
			require.NoError(t, err)
			require.False(t, alreadyUnlocked)

			alreadyUnlocked, err = walletSvc.Unlock(ctx, "")
			require.NoError(t, err)
			require.True(t, alreadyUnlocked)

			err = walletSvc.Lock(ctx)
			require.NoError(t, err)

			locked := walletSvc.IsLocked()
			require.True(t, locked)

			_, err = walletSvc.Unlock(ctx, password)
			require.NoError(t, err)

			locked = walletSvc.IsLocked()
			require.False(t, locked)
		})
	}
}

func TestNewBoardingAddress(t *testing.T) {
	ctx := context.Background()
	signerKey, _ := btcec.NewPrivateKey()
	boardingDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
	password := "password"

	testStoreData := sdktypes.Config{
		ServerUrl:           "127.0.0.1:7070",
		SignerPubKey:        signerKey.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		Network:             arklib.BitcoinRegTest,
		SessionDuration:     10,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		Dust:                1000,
		BoardingExitDelay:   boardingDelay,
		ForfeitAddress:      "bcrt1qzvqj",
	}

	store, err := inmemorystore.NewConfigStore()
	require.NoError(t, err)
	err = store.AddData(ctx, testStoreData)
	require.NoError(t, err)

	walletStore, err := inmemorywalletstore.NewWalletStore()
	require.NoError(t, err)

	walletSvc, err := singlekeywallet.NewBitcoinWallet(store, walletStore)
	require.NoError(t, err)

	_, err = walletSvc.Create(ctx, password, "")
	require.NoError(t, err)

	_, err = walletSvc.Unlock(ctx, password)
	require.NoError(t, err)

	// Baseline: GetAddresses returns exactly 1 default boarding address.
	_, _, boardingAddrs, _, err := walletSvc.GetAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, boardingAddrs, 1)
	defaultBoardingAddr := boardingAddrs[0].Address

	// Create a custom boarding script using a second owner key.
	ownerKey2, _ := btcec.NewPrivateKey()
	customScript := script.NewDefaultVtxoScript(
		ownerKey2.PubKey(), signerKey.PubKey(), boardingDelay,
	)

	addr, err := walletSvc.NewBoardingAddress(ctx, customScript)
	require.NoError(t, err)
	require.NotEmpty(t, addr.Address)
	require.NotEmpty(t, addr.Tapscripts)
	require.NotEqual(t, defaultBoardingAddr, addr.Address)

	// GetAddresses now returns 2 boarding addresses (default + custom).
	_, _, boardingAddrs, _, err = walletSvc.GetAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, boardingAddrs, 2)
	require.Equal(t, defaultBoardingAddr, boardingAddrs[0].Address)
	require.Equal(t, addr.Address, boardingAddrs[1].Address)

	// Adding the same script again is a no-op (deduplication).
	addr2, err := walletSvc.NewBoardingAddress(ctx, customScript)
	require.NoError(t, err)
	require.Equal(t, addr.Address, addr2.Address)

	_, _, boardingAddrs, _, err = walletSvc.GetAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, boardingAddrs, 2)

	// Adding a third distinct script produces 3 boarding addresses.
	ownerKey3, _ := btcec.NewPrivateKey()
	customScript2 := script.NewDefaultVtxoScript(
		ownerKey3.PubKey(), signerKey.PubKey(), boardingDelay,
	)
	addr3, err := walletSvc.NewBoardingAddress(ctx, customScript2)
	require.NoError(t, err)
	require.NotEqual(t, addr.Address, addr3.Address)

	_, _, boardingAddrs, _, err = walletSvc.GetAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, boardingAddrs, 3)
}

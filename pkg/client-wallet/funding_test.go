package wallet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-wallet/identity"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// Balance only formats the lock times the explorer reports and never compares them with the
// clock, so computing them once is enough. They differ so that a boarding entry can't pass for a
// redeem one.
var (
	boardingLockedUntil = time.Now().Add(time.Hour).Unix()
	redeemLockedUntil   = time.Now().Add(2 * time.Hour).Unix()
)

type stubBalance struct {
	spendable uint64
	locked    map[int64]uint64
}

// Balance must be tested from inside the package because the indexer it queries for the offchain
// balance can't be injected through the exported API.
func TestBalance(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		boarding := stubBalance{
			spendable: 2000, locked: map[int64]uint64{boardingLockedUntil: 3000},
		}
		redeem := stubBalance{
			spendable: 4000, locked: map[int64]uint64{redeemLockedUntil: 5000},
		}
		lockedBoarding := []types.LockedOnchainBalance{newLocked(boardingLockedUntil, 3000)}
		lockedRedeem := []types.LockedOnchainBalance{newLocked(redeemLockedUntil, 5000)}

		testCases := []struct {
			name          string
			utxoMaxAmount int64
			onchain       uint64
			boarding      stubBalance
			redeem        stubBalance
			expected      types.OnchainBalance
		}{
			{
				name:          "funds in every bucket",
				utxoMaxAmount: -1,
				onchain:       1000,
				boarding:      boarding,
				redeem:        redeem,
				expected: types.OnchainBalance{
					SpendableAmount:       7000,
					SpendableRedeemAmount: 4000,
					LockedAmount:          append(lockedBoarding, lockedRedeem...),
					LockedRedeemAmount:    lockedRedeem,
					LockedBoardingAmount:  lockedBoarding,
				},
			},
			{
				name:          "only onchain funds",
				utxoMaxAmount: -1,
				onchain:       1000,
				expected: types.OnchainBalance{
					SpendableAmount: 1000,
				},
			},
			{
				name:          "only boarding funds",
				utxoMaxAmount: -1,
				boarding:      boarding,
				expected: types.OnchainBalance{
					SpendableAmount:      2000,
					LockedAmount:         lockedBoarding,
					LockedBoardingAmount: lockedBoarding,
				},
			},
			{
				name:          "only redemption funds",
				utxoMaxAmount: -1,
				redeem:        redeem,
				expected: types.OnchainBalance{
					SpendableAmount:       4000,
					SpendableRedeemAmount: 4000,
					LockedAmount:          lockedRedeem,
					LockedRedeemAmount:    lockedRedeem,
				},
			},
			{
				name:          "boarding disabled by the server",
				utxoMaxAmount: 0,
				onchain:       1000,
				boarding:      boarding,
				redeem:        redeem,
				expected:      types.OnchainBalance{},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w := newTestWallet(t, tc.utxoMaxAmount)
				onchainAddr, _, boardingAddr, redeemAddr, err := w.getAddresses(t.Context())
				require.NoError(t, err)

				w.explorer = &stubExplorer{
					utxos: map[string][]clientlib.ExplorerUtxo{
						onchainAddr.Address: {{Amount: tc.onchain}},
					},
					balances: map[string]stubBalance{
						boardingAddr.Address: tc.boarding,
						redeemAddr.Address:   tc.redeem,
					},
				}

				balance, err := w.Balance(t.Context())
				require.NoError(t, err)

				got := balance.OnchainBalance
				require.Equal(t, tc.expected.SpendableAmount, got.SpendableAmount)
				require.Equal(t, tc.expected.SpendableRedeemAmount, got.SpendableRedeemAmount)
				require.ElementsMatch(t, tc.expected.LockedAmount, got.LockedAmount)
				require.ElementsMatch(t, tc.expected.LockedRedeemAmount, got.LockedRedeemAmount)
				require.ElementsMatch(
					t, tc.expected.LockedBoardingAmount, got.LockedBoardingAmount,
				)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			wallet      func(t *testing.T) *wallet
			expectedErr string
		}{
			{
				name: "wallet not initialized",
				wallet: func(t *testing.T) *wallet {
					w := newTestWallet(t, -1)
					w.identity = nil
					return w
				},
				expectedErr: ErrNotInitialized.Error(),
			},
			{
				name: "explorer failure",
				wallet: func(t *testing.T) *wallet {
					w := newTestWallet(t, -1)
					w.explorer = &stubExplorer{err: fmt.Errorf("explorer down")}
					return w
				},
				expectedErr: "explorer down",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				balance, err := tc.wallet(t).Balance(t.Context())
				require.ErrorContains(t, err, tc.expectedErr)
				require.Nil(t, balance)
			})
		}
	})
}

// stubExplorer serves fixed utxos and redeemed balances keyed by address.
type stubExplorer struct {
	clientlib.Explorer
	utxos    map[string][]clientlib.ExplorerUtxo
	balances map[string]stubBalance
	err      error
}

func (e *stubExplorer) GetUtxos(addrs []string) ([]clientlib.ExplorerUtxo, error) {
	if e.err != nil {
		return nil, e.err
	}
	var utxos []clientlib.ExplorerUtxo
	for _, addr := range addrs {
		utxos = append(utxos, e.utxos[addr]...)
	}
	return utxos, nil
}

func (e *stubExplorer) GetRedeemedVtxosBalance(
	addr string, _ arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	if e.err != nil {
		return 0, nil, e.err
	}
	return e.balances[addr].spendable, e.balances[addr].locked, nil
}

// stubIndexer reports no vtxos, so Balance has no offchain funds.
type stubIndexer struct {
	clientlib.Indexer
}

func (stubIndexer) GetVtxos(
	context.Context, ...clientlib.GetVtxosOption,
) (*clientlib.VtxosResponse, error) {
	return &clientlib.VtxosResponse{}, nil
}

func newTestWallet(t *testing.T, utxoMaxAmount int64) *wallet {
	t.Helper()

	store, err := identityinmemorystore.NewStore()
	require.NoError(t, err)
	identitySvc, err := identity.NewIdentity(store)
	require.NoError(t, err)
	_, err = identitySvc.Create(t.Context(), arklib.BitcoinRegTest, "password", "")
	require.NoError(t, err)

	signer, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return &wallet{
		ServerParams: &clientlib.ServerParams{
			SignerPubKey: signer.PubKey(),
			Network:      arklib.BitcoinRegTest,
			UnilateralExitDelay: arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 144,
			},
			BoardingExitDelay: arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 288,
			},
			UtxoMaxAmount: utxoMaxAmount,
		},
		identity: identitySvc,
		explorer: &stubExplorer{},
		indexer:  stubIndexer{},
		txLock:   &sync.RWMutex{},
	}
}

func newLocked(spendableAt int64, amount uint64) types.LockedOnchainBalance {
	return types.LockedOnchainBalance{
		SpendableAt: time.Unix(spendableAt, 0).Format(time.RFC3339),
		Amount:      amount,
	}
}

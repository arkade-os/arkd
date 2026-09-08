package wallet

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

// An offchain tx conserves value exactly: every sat of the selected coins that
// no receiver claims must come back as change, and the server rejects any
// output below its min vtxo amount. selectChangeCoins must therefore always
// leave a change that is either exactly 0 or at least minChangeAmount.
func TestSelectChangeCoins(t *testing.T) {
	const minChangeAmount = 330

	testCases := []struct {
		name              string
		btcAmountToSelect int64
		needChange        bool
		vtxoAmounts       []uint64
		expectedVtxos     int
		expectedChange    uint64
		expectedErr       string
	}{
		// The coins selected to cover an asset amount carry btc of their own.
		// When they carry more than the receivers ask for, that surplus is
		// change we already hold before selecting any further coin.
		{
			name:              "surplus above the min is used as is",
			btcAmountToSelect: -500,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     0,
			expectedChange:    500,
		},
		{
			name:              "surplus equal to the min is used as is",
			btcAmountToSelect: -330,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     0,
			expectedChange:    330,
		},
		{
			name:              "surplus below the min is topped up with another vtxo",
			btcAmountToSelect: -170,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     1,
			expectedChange:    1170,
		},
		{
			name:              "surplus below the min fails if no vtxo is left",
			btcAmountToSelect: -170,
			vtxoAmounts:       nil,
			expectedErr:       "not enough funds",
		},

		// The change left by the btc selection is subject to the same minimum.
		{
			name:              "change above the min is left as is",
			btcAmountToSelect: 500,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     1,
			expectedChange:    500,
		},
		{
			name:              "change below the min selects another vtxo",
			btcAmountToSelect: 1000,
			vtxoAmounts:       []uint64{1100, 1000},
			expectedVtxos:     2,
			expectedChange:    1100,
		},
		{
			name:              "change below the min fails if no vtxo is left",
			btcAmountToSelect: 1000,
			vtxoAmounts:       []uint64{1100},
			expectedErr:       "min change amount",
		},
		{
			name:              "an exactly covered amount leaves no change",
			btcAmountToSelect: 1000,
			vtxoAmounts:       []uint64{1000, 1000},
			expectedVtxos:     1,
			expectedChange:    0,
		},

		// needChange forces a change output even when the btc side balances
		// out, so that an asset change has an output to ride on.
		{
			name:              "nothing to select and no change needed",
			btcAmountToSelect: 0,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     0,
			expectedChange:    0,
		},
		{
			name:              "a needed change output is funded with another vtxo",
			btcAmountToSelect: 0,
			needChange:        true,
			vtxoAmounts:       []uint64{1000},
			expectedVtxos:     1,
			expectedChange:    1000,
		},
		{
			name:              "a needed change output fails if no vtxo is left",
			btcAmountToSelect: 0,
			needChange:        true,
			vtxoAmounts:       nil,
			expectedErr:       "not enough funds",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			selected, change, err := selectChangeCoins(
				tc.btcAmountToSelect, tc.needChange, makeTestVtxos(tc.vtxoAmounts),
				minChangeAmount, true,
			)

			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, selected, tc.expectedVtxos)
			require.Equal(t, tc.expectedChange, change)
			require.True(
				t, change == 0 || change >= minChangeAmount,
				"change %d is neither 0 nor at least the min %d", change, minChangeAmount,
			)

			// the tx must conserve value: the btc pulled in through the newly
			// selected coins, plus any surplus already carried by the asset
			// coins, is exactly what the change takes back out.
			selectedAmount := int64(0)
			for _, vtxo := range selected {
				selectedAmount += int64(vtxo.Amount)
			}
			require.Equal(
				t, selectedAmount-tc.btcAmountToSelect, int64(change),
				"selected coins and change don't balance out",
			)
		})
	}
}

func makeTestVtxos(amounts []uint64) []types.VtxoWithTapTree {
	vtxos := make([]types.VtxoWithTapTree, 0, len(amounts))
	for i, amount := range amounts {
		vtxos = append(vtxos, types.VtxoWithTapTree{
			Vtxo: types.Vtxo{
				Outpoint: types.Outpoint{Txid: fmt.Sprintf("vtxo-%d", i)},
				Amount:   amount,
			},
		})
	}
	return vtxos
}
